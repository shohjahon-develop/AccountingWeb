from django.contrib import admin
from .models import *

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'email', 'phone_number', 'role', 'is_active')
    list_filter = ('role', 'is_active')
    search_fields = ('full_name', 'email', 'phone_number')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('get_report_types', 'client', 'accountant', 'status', 'total_price', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('client__full_name', 'accountant__user__full_name')

    def get_report_types(self, obj):
        return ", ".join([rt.name for rt in obj.report_types.all()])  # Hisobot turlarini vergul bilan chiqarish
    get_report_types.short_description = "Hisobot turlari"

@admin.register(ReportComment)
class ReportCommentAdmin(admin.ModelAdmin):
    list_display = ('report', 'author', 'created_at')
    search_fields = ('report__report_type__name', 'author__full_name')

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient', 'created_at')
    search_fields = ('sender__full_name', 'recipient__full_name')

@admin.register(PaymentCard)
class PaymentCardAdmin(admin.ModelAdmin):
    list_display = ('card_number', 'owner_name', 'bank_name')
    search_fields = ('owner_name', 'bank_name')

@admin.register(ReportType)
class ReportTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'price')
    search_fields = ('name',)

@admin.register(Accountant)
class AccountantAdmin(admin.ModelAdmin):
    list_display = ('user',  'certifications', 'fee')

@admin.register(AboutUs)
class AboutUsAdmin(admin.ModelAdmin):
    list_display = ('title',)
    search_fields = ('title', 'text')