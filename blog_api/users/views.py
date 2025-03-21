from django.shortcuts import render, redirect
from django.contrib.auth import authenticate,login
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import BlogPostSerializer, UserSerializer
from .models import Blogapi, User
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from django.shortcuts import redirect

from rest_framework import generics, permissions, filters
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from django.db.models import Q
from .serializers import BlogPostSerializer
from .permissions import IsOwnerOrReadOnly
from django.core.exceptions import PermissionDenied
from rest_framework.pagination import PageNumberPagination
from django.core.paginator import Paginator


def register_page(request):
    return render(request, 'register.html')

def login_page(request):
    return render(request, 'login.html')

def home(request):
    return render(request, 'home.html')

def create_blog(request):
    return render(request,'create_blog.html')

def blog_list(request):
    
    if not request.user.is_authenticated:
        return redirect('/login_page/')
    search=request.GET.get('title','')
    blp = Blogapi.objects.filter(author=request.user)
    blp=blp.filter(title__icontains=search)

    paginator = Paginator(blp, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)  
    return render(request, 'blog_list.html', {'data': page_obj})

def public_bloglist(request):
    search=request.GET.get('title','')
    blp=Blogapi.objects.all()
    blp=blp.filter(title__icontains=search)

    paginator = Paginator(blp, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request,'public_bloglist.html', {'data': page_obj})

def edit_blog(request):
    return render(request,'edit_blog.html')

# class RegisterView(APIView):
#     def post(self, request):
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return redirect('/users/login_page/') 
#         return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "hasError": False,
                "errorCode": -1,
                "message": "User registered successfully",
                "debugMessage": "",
                "redirect_url": "/login_page/"
            }, status=status.HTTP_201_CREATED)

        return Response({
            "hasError": True,
            "errorCode": 400,
            "message": "Validation error",
            "debugMessage": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            access_token = str(AccessToken.for_user(user))
            refresh_token = str(RefreshToken.for_user(user))

            return Response({
                "hasError": False,
                "errorCode": -1,
                "message": "Login successful",
                "debugMessage": "",
                "data": {
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "hasError": True,
                "errorCode": 401,
                "message": "Invalid credentials",
                "debugMessage": "Incorrect username or password"
            }, status=status.HTTP_401_UNAUTHORIZED)
        

class BlogPostListCreateView(generics.ListCreateAPIView):
    queryset = Blogapi.objects.select_related('author').all()  
    serializer_class = BlogPostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [filters.SearchFilter]
    search_fields = ['title']
    pagination_class = None 

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            return Blogapi.objects.filter(Q(author=user) | Q(status="published")).select_related('author')
        return Blogapi.objects.filter(status="published").select_related('author')

    def perform_create(self, serializer):
        if serializer.is_valid():
            serializer.save(author=self.request.user)
            return Response({
                "hasError": False,
                "errorCode": -1,
                "message": "Blog post created successfully",
                "debugMessage": "",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            "hasError": True,
            "errorCode": 400,
            "message": "Validation error",
            "debugMessage": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class BlogPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Blogapi.objects.select_related('author').all()
    serializer_class = BlogPostSerializer
    permission_classes = [IsOwnerOrReadOnly]

    def get_queryset(self):
        return Blogapi.objects.filter(Q(author=self.request.user) | Q(status="published"))

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user != instance.author:
            return Response({
                "hasError": True,
                "errorCode": 403,
                "message": "Permission denied",
                "debugMessage": "You cannot update this blog post"
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response({
                "hasError": False,
                "errorCode": -1,
                "message": "Blog post updated successfully",
                "debugMessage": "",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            "hasError": True,
            "errorCode": 400,
            "message": "Validation error",
            "debugMessage": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user != instance.author:
            return Response({
                "hasError": True,
                "errorCode": 403,
                "message": "Permission denied",
                "debugMessage": "You cannot delete this blog post"
            }, status=status.HTTP_403_FORBIDDEN)

        instance.delete()
        return Response({
            "hasError": False,
            "errorCode": -1,
            "message": "Blog post deleted successfully",
            "debugMessage": ""
        }, status=status.HTTP_200_OK)



