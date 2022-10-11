from rest_framework import serializers

from users.serializers import ProfileSerializer
from .models import Post, Comment

class CommentSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    
    class Meta :
        model = Comment
        fields = ("pk", "profile", "post", "text", "likes")

class CommentCreateSerializer(serializers.ModelSerializer):
    class Meta :
        model = Comment
        fields = ("post", "text")


class PostSerializer(serializers.ModelSerializer) :
    profile = ProfileSerializer(read_only=True) # nested serializer # 이 코드가 없다면 profile 필드는 단순히 pk 값만 나타낸다..?
    comments = CommentSerializer(many=True, read_only=True)

    class Meta :
        model = Post
        fields = ("pk", "profile", "title", "body", "image", "published_date", "likes", "comments")

class PostCreateSerializer(serializers.ModelSerializer) :
    class Meta :
        model = Post
        fields = ("title", "category", "body", "image")