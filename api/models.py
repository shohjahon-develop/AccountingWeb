from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, phone_number, full_name, password=None, role='mijoz', **extra_fields):
        if not email:
            raise ValueError("Email kiritish majburiy")
        email = self.normalize_email(email)
        user = self.model(email=email, phone_number=phone_number, full_name=full_name, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, full_name, password):
        user = self.create_user(email, phone_number, full_name, password, role='admin')
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('mijoz', 'Mijoz'),
        ('buxgalter', 'Buxgalter'),
        ('admin', 'Admin'),
    ]

    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    full_name = models.CharField(max_length=255)
    img = models.ImageField(upload_to='user_images/', blank=True, null=True)  # Oldingi o‘zgarishdan qolgan

    # Mijozlar uchun
    company_name = models.CharField(max_length=255, blank=True, null=True)
    stir = models.CharField(max_length=20, blank=True, null=True)

    # Buxgalterga tegishli maydonlar olib tashlanadi
    # experience, specialty, address, skills, languages, bio olib tashlanadi

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='mijoz')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number', 'full_name']

    def __str__(self):
        return f"{self.full_name} - {self.role}"

class Accountant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    certifications = models.TextField(blank=True, null=True)
    fee = models.PositiveIntegerField()
    experience = models.IntegerField(blank=True, null=True)  # Yangi
    specialty = models.CharField(max_length=100, blank=True, null=True)  # Yangi
    address = models.CharField(max_length=255, blank=True, null=True)  # Yangi
    skills = models.TextField(blank=True, null=True)  # Yangi
    languages = models.CharField(max_length=255, blank=True, null=True)  # Yangi
    bio = models.TextField(blank=True, null=True)  # Yangi

    def __str__(self):
        return self.user.full_name



class ReportType(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.name



class Report(models.Model):
    STATUS_CHOICES = [
        ('new', 'Yangi'),
        ('in_review', 'Ko‘rib chiqilmoqda'),
        ('approved', 'Tasdiqlandi'),
        ('rejected', 'Rad etildi'),
    ]

    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    accountant = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_reports')
    report_types = models.ManyToManyField(ReportType)  # Hisobot turlari
    file = models.FileField(upload_to='reports/')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    created_at = models.DateTimeField(auto_now_add=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    def calculate_total_price(self):
        if not self.pk:  # Agar ID hali mavjud bo‘lmasa
            return 0
        return sum(rt.price for rt in self.report_types.all())

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)  # Avval saqlaymiz (ID hosil bo‘ladi)
        self.total_price = self.calculate_total_price()  # Keyin narxni hisoblaymiz
        super().save(update_fields=['total_price'])  # Narxni yangilaymiz

    def __str__(self):
        return f"{self.client.full_name} - {self.total_price} so‘m"




class ReportComment(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.author.full_name}: {self.comment[:30]}..."


# Xabarlar modeli
class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.full_name} → {self.recipient.full_name}: {self.message[:30]}..."


class PaymentCard(models.Model):
    card_number = models.CharField(max_length=16, unique=True)
    owner_name = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.bank_name} - {self.card_number[-4:]}"


class AboutUs(models.Model):
    img = models.ImageField(upload_to='aboutus/', blank=True, null=True)
    title = models.CharField(max_length=255)
    text = models.TextField()

    def __str__(self):
        return self.title





























