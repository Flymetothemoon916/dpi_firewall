from django.urls import path
from . import views

urlpatterns = [
    path('', views.rule_list, name='rule_list'),
    path('<int:rule_id>/', views.rule_detail, name='rule_detail'),
    path('create/', views.rule_create, name='rule_create'),
    path('<int:rule_id>/edit/', views.rule_edit, name='rule_edit'),
    path('<int:rule_id>/toggle/', views.rule_toggle, name='rule_toggle'),
    path('blacklist/', views.blacklist, name='blacklist'),
    path('blacklist/<int:ip_id>/delete/', views.blacklist_delete, name='blacklist_delete'),
    path('whitelist/', views.whitelist, name='whitelist'),
    path('whitelist/<int:ip_id>/delete/', views.whitelist_delete, name='whitelist_delete'),
] 