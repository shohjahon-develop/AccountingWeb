import random

from django.conf import settings
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import generics, status, viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser


from .serializers import *
from django.contrib.auth import get_user_model

User = get_user_model()

class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]


class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            return Response({
                "message": "Tizimga muvaffaqiyatli kirdingiz!",
                "tokens": response.data
            }, status=status.HTTP_200_OK)
        return response



class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [permissions.IsAdminUser]  # Faqat admin ko‘ra oladi

    def get_queryset(self):
        role = self.request.query_params.get('role')
        if role:
            return User.objects.filter(role=role)  # Masalan: /api/users/?role=buxgalter
        return super().get_queryset()




class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserProfileUpdateView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

# Parolni qayta tiklash /////////////////////////////////////////////////////////////////

# 1️⃣ Parolni tiklash so‘rovi
class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}"

        send_mail(
            "Parolni tiklash",
            f"Parolingizni tiklash uchun quyidagi havolaga bosing: {reset_link}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        return Response({"detail": "Parolni tiklash bo‘yicha email yuborildi."}, status=status.HTTP_200_OK)

# 2️⃣ Parolni yangilash
class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        new_password = serializer.validated_data['new_password']
        user.set_password(new_password)
        user.save()

        return Response({"detail": "Parol muvaffaqiyatli o‘zgartirildi."}, status=status.HTTP_200_OK)





class ReportTypeViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ReportType.objects.all()
    serializer_class = ReportTypeSerializer
    permission_classes = [permissions.AllowAny]

class AccountantViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Accountant.objects.all()
    serializer_class = AccountantSerializer
    permission_classes = [permissions.AllowAny]

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return Report.objects.none()  # Agar foydalanuvchi login qilmagan bo‘lsa, bo‘sh queryset qaytarish
        return Report.objects.filter(client=self.request.user)

    def perform_create(self, serializer):
        serializer.save(client=self.request.user)

    @action(detail=False, methods=['GET'], permission_classes=[permissions.IsAuthenticated])
    def accountant_statistics(self, request):
        accountant = request.user
        if accountant.role != 'buxgalter':
            return Response({"error": "Faqat buxgalterlar statistikani ko‘ra oladi."}, status=403)

        total_reports = Report.objects.filter(accountant=accountant).count()
        completed_reports = Report.objects.filter(accountant=accountant, status='completed').count()
        pending_reports = Report.objects.filter(accountant=accountant, status='pending').count()
        total_earnings = sum(
            report.price for report in Report.objects.filter(accountant=accountant, status='completed'))

        return Response({
            "total_reports": total_reports,
            "completed_reports": completed_reports,
            "pending_reports": pending_reports,
            "total_earnings": total_earnings
        })

    @action(detail=True, methods=['PATCH'], permission_classes=[permissions.IsAuthenticated])
    def update_status(self, request, pk=None):
        """Hisobotning statusini yangilash."""
        report = self.get_object()
        serializer = ReportSerializer(report, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ReportCommentViewSet(viewsets.ModelViewSet):
    queryset = ReportComment.objects.all()
    serializer_class = ReportCommentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return Message.objects.none()  # Agar foydalanuvchi autentifikatsiya qilinmagan bo‘lsa, bo‘sh queryset qaytarish

        return Message.objects.filter(recipient=self.request.user) | Message.objects.filter(sender=self.request.user)

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)


class PaymentCardViewSet(viewsets.ModelViewSet):
    queryset = PaymentCard.objects.all()
    serializer_class = PaymentCardSerializer
    permission_classes = [permissions.IsAdminUser]

    @action(detail=False, methods=['GET'], permission_classes=[permissions.AllowAny])
    def get_random_card(self, request):
        cards = PaymentCard.objects.all()
        if not cards:
            return Response({"error": "Hech qanday karta topilmadi."}, status=404)
        random_card = random.choice(cards)
        return Response(PaymentCardSerializer(random_card).data)



class UserAdminViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({"message": "Foydalanuvchi o‘chirildi"}, status=status.HTTP_204_NO_CONTENT)












