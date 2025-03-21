from django.contrib import admin
from django.urls import include, path
from .import views

urlpatterns = [
    path('register_page/',views.register_page,name='register_page'),
    path('register-api/', views.RegisterView.as_view(), name='register_api'),

    path("login-api/", views.LoginView.as_view(), name="login-api"),
    path('', views.login_page, name='login_page'),

    path('home/',views.home,name='home'),
    path('create_blog/',views.create_blog,name='create_blog'),
    path('createblogpost-api/', views.BlogPostListCreateView.as_view(), name='createblogpost-api'),

    path('blog_list/',views.blog_list,name='blog_list'),
    path('edit_blog/',views.edit_blog,name='edit_blog'),
    path('public_bloglist/',views.public_bloglist,name='public_bloglist'),
    path('blog-api/<int:pk>/', views.BlogPostDetailView.as_view(), name='blog_detail'),

]