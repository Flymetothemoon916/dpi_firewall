from django.urls import path
from . import views

urlpatterns = [
    path('', views.packet_list, name='packet_list'),
    path('<int:packet_id>/', views.packet_detail, name='packet_detail'),
    # 数据包捕获功能已移至命令行工具
    path('protocols/', views.protocols, name='protocols'),
] 