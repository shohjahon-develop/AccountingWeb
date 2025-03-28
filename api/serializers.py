from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model

from api.models import *

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'phone_number', 'password', 'role',
                  'company_name', 'stir', 'experience', 'specialty']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        role = data.get('role', 'mijoz')
        if role == 'mijoz':
            # Mijozlar faqat company_name va stir kiritishi mumkin
            data.pop('experience', None)
            data.pop('specialty', None)
        elif role == 'buxgalter':
            # Buxgalterlar faqat experience va specialty kiritishi mumkin
            data.pop('company_name', None)
            data.pop('stir', None)
        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)




class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'phone_number', 'role',
                  'company_name', 'stir', 'experience', 'specialty']


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'phone_number', 'company_name', 'stir', 'experience', 'specialty']
        extra_kwargs = {
            'experience': {'required': False},
            'specialty': {'required': False},
            'company_name': {'required': False},
            'stir': {'required': False},
        }


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Bunday email ro'yxatdan o'tmagan.")
        return value

# 2️⃣ Kodni tekshirish
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
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    fee = serializers.DecimalField(max_digits=10, decimal_places=2)  # fee - buxgalterning narxi

    class Meta:
        model = Accountant
        fields = ['id', 'full_name', 'email', 'experience', 'specialty', 'certifications', 'fee']


class ReportSerializer(serializers.ModelSerializer):
    report_types = serializers.StringRelatedField(many=True, read_only=True)  # To‘g‘ri ManyToManyField

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
    sender_name = serializers.CharField(source='sender.full_name', read_only=True)
    recipient_name = serializers.CharField(source='recipient.full_name', read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'sender', 'sender_name', 'recipient', 'recipient_name', 'message', 'created_at']
        read_only_fields = ['sender', 'created_at']



class PaymentCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentCard
        fields = '__all__'




























































