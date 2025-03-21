from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Blogapi

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user
    
class BlogPostSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username') 

    class Meta:
        model = Blogapi
        fields = ['id', 'title', 'content', 'author', 'created_at', 'updated_at', 'status']
