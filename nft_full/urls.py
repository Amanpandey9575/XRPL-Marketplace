from django.urls import path
from nft_api import views
from django.contrib import admin
from nft_api.views import  *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('mint/', views.mint_nft_view, name='mint_nft'),
    path('sell/', views.create_sell_offer_view, name='create_sell_offer'),
    path('accept_sell_offer/', views.accept_sell_offer_view, name='accept_sell_offer'),
    path('create_buy_offer/', views.create_buy_offer_view, name='create_buy_offer'),
    path('get_offers/', views.get_offers_view, name='get_offers'),
    # path('accept_buy_offer/', views.accept_buy_offer_view, name='accept_buy_offer'),
    path('cancel_offer/', views.cancel_offer_view, name='cancel_offer'),
    path('login/',views.userlogin ,name='login'),
    path('',views.register ,name="register"),
    path('forgot-password/' , views.ForgotPassword , name="forgot_password"),
    path('change-password/<token>/' , views.ChangePassword , name="change_password"),
    path('home/', views.profile, name='home'),
    path('broker_sale/', views.broker_sale_view, name='broker_sale'),
    path('set_minter/', views.set_minter_view, name='set_minter'),
    path('mint_other/', views.mint_other_view, name='mint_other'),
    path('getdata/', views.xrpl_accounts, name='getdata'),
    path('find_nfts/', views.find_nfts, name='find_nfts'),   
    path('accept_buy_offer/', views.accept_buy_offer_view, name='accept_buy_offer'),
    path('collections/', views.collections, name='collections'),
    path('explore/', views.explore, name='explore'),
    path('explore/<str:nft_id>/', views.nft_detail, name='nft_detail'),
    path('xumm/', XummView.as_view(), name='xumm_view'),
    path('xumm_callback/', XummCallbackView.as_view(), name='xumm-callback'),
    path('collections/<str:account_address>/',views.All_nfts,name='allnfts'),
    path('collections/<str:account_address>/<str:nft_id>/',views.All_nfts,name='explore_nft'),
    # path('mint_nft/', MintNFTView.as_view(), name='mint_nft'),
    # path('handle-transaction/', views.handle_transaction, name='handle_transaction'),
    # path('handle_payload_event/', views.handle_payload_event, name='handle_payload_event'),

    


]