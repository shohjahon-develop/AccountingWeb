from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'reports/types', ReportTypeViewSet)
router.register(r'accountants', AccountantViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'report-comments', ReportCommentViewSet)
router.register(r'messages', MessageViewSet)
router.register(r'payment-cards', PaymentCardViewSet)
router.register(r'admin-users', UserAdminViewSet, basename='admin-users')
router.register(r'aboutus', AboutUsViewSet, basename='aboutus')
router.register(r'chats', ChatViewSet, basename='chats')
router.register(r'admin-chats', AdminChatViewSet, basename='admin-chats')

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/edit/', UserProfileUpdateView.as_view(), name='profile-edit'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

path('password-change/', PasswordChangeView.as_view(), name='password_change'),
    path('', include(router.urls)),
]
