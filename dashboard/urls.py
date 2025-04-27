from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('alerts/', views.alerts, name='alerts'),
    path('alerts/mark-as-read/<int:alert_id>/', views.mark_alert_as_read, name='mark_alert_as_read'),
    path('traffic-stats/', views.traffic_stats, name='traffic_stats'),
    path('get-dashboard-data/', views.get_dashboard_data, name='get_dashboard_data'),
    path('performance/', views.performance_monitor, name='performance_monitor'),
    path('get-performance-data/', views.get_performance_data, name='get_performance_data'),
] 