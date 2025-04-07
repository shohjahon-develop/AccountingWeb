from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from api.models import *

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    # Buxgalter uchun qo‘shimcha maydonlarni alohida qo‘shish
    experience = serializers.IntegerField(required=False, allow_null=True)
    specialty = serializers.CharField(max_length=100, required=False, allow_blank=True, allow_null=True)
    address = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    skills = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    languages = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    bio = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    certifications = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    fee = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, default=0)

    class Meta:
        model = User
        fields = [
            'full_name', 'email', 'phone_number', 'password', 'role',
            'company_name', 'stir',  # Mijoz uchun
            'experience', 'specialty', 'address', 'skills', 'languages', 'bio',  # Buxgalter uchun
            'certifications', 'fee'  # Accountant modelidan
        ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        role = data.get('role', 'mijoz')
        if role == 'mijoz':
            # Mijoz uchun faqat kerakli maydonlar
            required_fields = ['company_name', 'stir']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({field: f"{field} mijoz uchun majburiy."})
            # Buxgalter maydonlarini olib tashlash
            for field in ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']:
                data.pop(field, None)
        elif role == 'buxgalter':
            # Buxgalter uchun faqat kerakli maydonlar
            required_fields = ['experience', 'specialty', 'address', 'skills', 'languages', 'bio']
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError({field: f"{field} buxgalter uchun majburiy."})
            # Mijoz maydonlarini olib tashlash
            for field in ['company_name', 'stir']:
                data.pop(field, None)
        return data

    def create(self, validated_data):
        # Buxgalterga tegishli ma'lumotlarni alohida ajratamiz
        accountant_fields = ['experience', 'specialty', 'address', 'skills', 'languages', 'bio', 'certifications', 'fee']
        accountant_data = {field: validated_data.pop(field, None) for field in accountant_fields}

        # User obyektini yaratamiz
        user = User.objects.create_user(**validated_data)

        # Agar role buxgalter bo'lsa, Accountant obyektini yaratamiz
        if user.role == 'buxgalter':
            Accountant.objects.create(
                user=user,
                certifications=accountant_data['certifications'],
                fee=accountant_data['fee'],
                experience=accountant_data['experience'],
                specialty=accountant_data['specialty'],
                address=accountant_data['address'],
                skills=accountant_data['skills'],
                languages=accountant_data['languages'],
                bio=accountant_data['bio']
            )
        return user

# Qolgan serializerlar o‘zgarmaydi
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        return token

class LoginResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    tokens = CustomTokenObtainPairSerializer()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'phone_number', 'role', 'company_name', 'stir', 'img']

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'phone_number', 'company_name', 'stir', 'img']
        extra_kwargs = {
            'company_name': {'required': False},
            'stir': {'required': False},
            'img': {'required': False},
        }

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Bunday email ro'yxatdan o'tmagan.")
        return value

class AboutUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AboutUs
        fields = ['id', 'img', 'title', 'text']

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uidb64']))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError):
            raise serializers.ValidationError("Noto'g'ri havola yoki token.")

        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError("Token noto‘g‘ri yoki eskirgan.")

        attrs['user'] = user
        return attrs

class ReportTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportType
        fields = '__all__'

class AccountantSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        write_only=True,
        source='user'
    )
    fee = serializers.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        model = Accountant
        fields = ['id', 'user', 'user_id', 'certifications', 'fee',
                  'experience', 'specialty', 'address', 'skills', 'languages', 'bio']

    def validate_user_id(self, value):
        if Accountant.objects.filter(user=value).exists():
            raise serializers.ValidationError("Bu foydalanuvchi allaqachon buxgalter sifatida ro'yxatdan o'tgan.")
        if value.role != 'buxgalter':
            raise serializers.ValidationError("Faqat 'buxgalter' roli bo'lgan foydalanuvchilar Accountant sifatida qo'shilishi mumkin.")
        return value

class ReportSerializer(serializers.ModelSerializer):
    report_types = ReportTypeSerializer(many=True, read_only=True)
    accountant = AccountantSerializer(read_only=True)
    client = UserSerializer(read_only=True)

    class Meta:
        model = Report
        fields = ['id', 'client', 'accountant', 'report_types', 'status', 'total_price', 'created_at']
        extra_kwargs = {'status': {'write_only': True}}

class ReportCommentSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.full_name', read_only=True)

    class Meta:
        model = ReportComment
        fields = ['id', 'report', 'author', 'author_name', 'comment', 'created_at']
        read_only_fields = ['author', 'created_at']

class MessageSerializer(serializers.ModelSerializer):
    from_user = serializers.SerializerMethodField()  # "from" uchun
    to_user = serializers.SerializerMethodField()    # "to" uchun

    class Meta:
        model = Message
        fields = ['id', 'from_user', 'to_user', 'message', 'created_at']
        read_only_fields = ['id', 'created_at']

    def get_from_user(self, obj):
        return {
            "id": obj.sender.id,
            "role": obj.sender.role,
            "name": obj.sender.full_name
        }

    def get_to_user(self, obj):
        return {
            "id": obj.recipient.id,
            "role": obj.recipient.role,
            "name": obj.recipient.full_name
        }
class PaymentCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentCard
        fields = '__all__'

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=6)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Joriy parol noto‘g‘ri.")
        return value






















































