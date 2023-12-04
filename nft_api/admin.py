from django.contrib import admin
from .models import *
from .models import XRPL_Model

@admin.register(NFT)
class NFTAdmin(admin.ModelAdmin):
    list_display = ('title', 'description','author', 'image')
    search_fields = ('title', 'description','author', 'image')

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user','forget_password_token', 'created_at')
    search_fields = ('id', 'user','forget_password_token', 'created_at')


@admin.register(XRPL_Model)
class XRPLModelAdmin(admin.ModelAdmin):
    list_display = ('user','account_address', 'seed', 'created_at')
    search_fields = ('user','account_address', 'seed', 'created_at')


