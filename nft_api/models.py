from django.db import models
from django.contrib.auth.models import User
from datetime import datetime


class Profile(models.Model):
    user = models.OneToOneField(User , on_delete=models.CASCADE)
    forget_password_token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username

class NFT(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    author = models.CharField(max_length=50)
    image = models.ImageField(upload_to='nft_images/')

    def __str__(self):
        return self.title

class XRPL_Model(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    account_address = models.CharField(max_length=100)
    seed = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return f"{self.user.username}'s XRPL Account"
