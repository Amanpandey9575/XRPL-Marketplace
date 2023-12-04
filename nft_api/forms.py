# nftapp/forms.py
from django import forms
from .models import *
from django.contrib.auth.forms import (UserCreationForm, AuthenticationForm, SetPasswordForm, UsernameField, PasswordChangeForm, PasswordResetForm)
from django.contrib.auth.models import User
from django.utils.translation import gettext, gettext_lazy as _
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError



from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField

from .models import User

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()
    username = forms.CharField(label='Enter Username', help_text='* Username should not have any space' , min_length=4, max_length=150)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

from django.contrib.auth.forms import AuthenticationForm
class UserLoginForm(AuthenticationForm):
    class Meta:
        model = User  # You should import the User model from your authentication system
        fields = ('username', 'password')

class NFTForm(forms.Form):
    seed = forms.CharField(widget=forms.HiddenInput) 
    title = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Enter a Title'}),) 
    description = forms.CharField(max_length=1000,  widget=forms.TextInput(attrs={'placeholder': 'Enter a Description'}),)
    # author = forms.CharField(max_length=50,  widget=forms.TextInput(attrs={'placeholder': 'Enter you name'}),)
    image = forms.ImageField()



class SellOfferForm(forms.Form):
    seed = forms.CharField(widget=forms.HiddenInput)
    amount = forms.DecimalField(widget=forms.TextInput(attrs={'placeholder': 'Amount of the sell offer in drops'}))
    nftoken_id = forms.CharField(max_length=64, widget=forms.HiddenInput)
    # expiration = forms.IntegerField(required=False, widget=forms.TextInput(attrs={'placeholder': 'Enter a number of seconds until expiration'}))

class AcceptSellOfferForm(forms.Form):
    offer_index = forms.CharField(label='Offer Index', max_length=100)

class BuyOfferForm(forms.Form):
    seed = forms.CharField(max_length=64, widget=forms.HiddenInput)
    amount = forms.DecimalField(widget=forms.TextInput(attrs={'placeholder': 'Enter a number of seconds until expiration'}))
    nft_id = forms.CharField(max_length=64, widget=forms.HiddenInput)
    owner = forms.CharField(widget=forms.HiddenInput)
    # expiration = forms.IntegerField(required=False)


class AcceptBuyOfferForm(forms.Form):
    seed = forms.CharField(max_length=64, label='Seed')
    offer_index = forms.CharField(label='Offer Index')


class CancelOfferForm(forms.Form):
    seed = forms.CharField(max_length=64, widget=forms.PasswordInput)
    offer_id = forms.IntegerField() 

class NFTIdForm(forms.Form):
    nft_id = forms.CharField(label='NFT ID', max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Click on any of the NFTs avialabe in the list'}))


class BrokerSaleForm(forms.Form):
    seed = forms.CharField(max_length=100)
    sell_offer_index = forms.IntegerField()
    buy_offer_index = forms.IntegerField()
    broker_fee = forms.DecimalField(max_digits=10, decimal_places=2)


class SetMinterForm(forms.Form):
    seed = forms.CharField(label='Seed', max_length=100)
    minter = forms.CharField(label='Minter', max_length=100)

class MintOtherForm(forms.Form):
    seed = forms.CharField(label='Seed', max_length=100)
    uri = forms.CharField(label='URI', max_length=100)
    flags = forms.IntegerField(label='Flags')
    transfer_fee = forms.DecimalField(label='Transfer Fee')
    taxon = forms.IntegerField(label='Taxon')
    issuer = forms.CharField(label='Issuer', max_length=100)