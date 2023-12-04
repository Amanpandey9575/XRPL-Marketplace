 # nftapp/views.py
from django.shortcuts import render, redirect
from xrpl.models.requests import NFTSellOffers, NFTBuyOffers, AccountObjects, AccountNFTs
from nft_api.forms import *
from xrpl.wallet import Wallet
from xrpl.transaction import submit_and_wait
from xrpl.models.transactions.nftoken_mint import NFTokenMint, NFTokenMintFlag
from xrpl.wallet import generate_faucet_wallet
from xrpl.models.transactions import NFTokenAcceptOffer, NFTokenCancelOffer, NFTokenCreateOffer
from xrpl.clients import JsonRpcClient
import base58
import binascii
import urllib.parse
import json
import xrpl
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login
from django.contrib import messages
from .models import XRPL_Model
from django.db import IntegrityError
from nft_api.constant import ipfs_base_port, ipfs_url_port
from datetime import datetime, timedelta
from django.http import HttpResponseBadRequest
from xrpl.models.requests import AccountOffers
from .helpers import send_forgot_password_mail
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json
import requests
from django.http import JsonResponse, HttpResponseRedirect
from django.views import View
from django.urls import reverse




def register(request):
    error_message = None  # Initialize error_message as None

    if request.method == 'POST':
        try:
            name = request.POST.get('Name')
            email = request.POST.get('Email')
            password = request.POST.get('CreatePassword')
            
            # Check if a user with the same username or email already exists
            if User.objects.filter(username=name).exists() or User.objects.filter(email=email).exists():
                raise IntegrityError("User already exists.")
            
            # Create a new user
            user = User.objects.create_user(name, email, password=password)
            user.save()

            profile_obj = Profile.objects.create(user = user)
            profile_obj.save()

            # Create a new wallet for the user
            client = JsonRpcClient("https://s.altnet.rippletest.net:51234/")
            wallet = generate_faucet_wallet(client, debug=True)
            account_address = wallet.classic_address
            seed = wallet.seed

            xrpl_data = XRPL_Model.objects.create(user=user, account_address=account_address, seed=seed)
            xrpl_data.save()
            
            user = authenticate(request, username=name, password=password)
            if user is not None:
                login(request, user)

            return redirect('home')

        except IntegrityError:
            error_message = "User already exists. Please choose a different username or email."

    context = {
        'error_message': error_message,  # Include error_message in the context
    }

    return render(request, "nft_api/register.html", context)


from django.contrib.auth import authenticate, login
def userlogin(request):
    error_message = None
    if request.method == 'POST':
        us = request.POST.get('username')
        ps = request.POST.get('password')
        user = authenticate(request, username=us, password=ps)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            error_message = "Invalid username or password. Please enter the correct username and password."
    context = {
        'error_message': error_message, 
    }
    return render(request, "nft_api/login.html", context)


import uuid
def ForgotPassword(request):
    try:
        if request.method == 'POST':
            name = request.POST.get('username')  
            print("Name: ", name)

            if not User.objects.filter(username=name).first():
                messages.success(request, 'User not found with this name, please mind the case(Upper/Lower)!.')
                return redirect('/forgot-password/')
            
            user_obj = User.objects.get(username = name)
            token = str(uuid.uuid4())
            profile_obj= Profile.objects.get(user = user_obj)
            profile_obj.forget_password_token = token
            profile_obj.save()
            send_forgot_password_mail(user_obj.email , token)
            messages.success(request, 'An Email Has Been Sent.')
            print("Email is sent")
            return redirect('/forgot-password/')
    
    except Exception as e:
        print(e)
    return render(request , 'nft_api/forgot-password.html')


def ChangePassword(request , token):
    context = {}
    
    
    try:
        profile_obj = Profile.objects.filter(forget_password_token = token).first()
        context = {'user_id' : profile_obj.user.id}
        
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('reconfirm_password')
            user_id = request.POST.get('user_id')
            
            if user_id is  None:
                messages.success(request, 'No user id found.')
                return redirect(f'/change-password/{token}/')
                
            
            if  new_password != confirm_password:
                messages.success(request, 'both should  be equal.')
                return redirect(f'/change-password/{token}/')                         
            
            user_obj = User.objects.get(id = user_id)
            user_obj.set_password(new_password)
            user_obj.save()
            return redirect('/login/')
                    
    except Exception as e:
        print(e)
    return render(request , 'nft_api/change-password.html' , context)


import random
def profile(request):
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect unauthenticated users to the login page

    xrpl_data = None 
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass 

        initial_issuer_address = xrpl_data.account_address if xrpl_data else ""
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)
        issuerAddr = initial_issuer_address
        get_account_nfts = client.request(AccountNFTs(account=issuerAddr))
        nft_int = 1
        NFTs = []
        URI = []

        for nft in get_account_nfts.result['account_nfts']:
            encoded_uri = nft['URI']

            try:
                decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
            except UnicodeDecodeError:
                decoded_uri = "Invalid or non-UTF-8 data"
            
            NFTs.append(nft['NFTokenID'])
            URI.append("https://gateway.pinata.cloud/ipfs/" + decoded_uri)

            nft_int += 1

    NFTs = NFTs
    nft_length = len(NFTs)
    URI = URI
    # random_uri = []
    final_random_uri =None
    if len(URI) !=0:
        final_random_uri=URI[random.randint(0, len(URI) - 1)]
    nft_uri_pairs = zip(NFTs, URI)
    
    
    
    if request.method == 'POST':
        form = NFTIdForm(request.POST)
        if form.is_valid():
            nft_id = form.cleaned_data['nft_id']
            
            testnet_url = "https://s.altnet.rippletest.net:51234/"  # Define your testnet URL
            client = JsonRpcClient(testnet_url)

            offers_request = NFTBuyOffers(nft_id=nft_id)
            response = client.request(offers_request)
            buy_offers = json.dumps(response.result, indent=4)

            sell_offers_request = NFTSellOffers(nft_id=nft_id)
            response = client.request(sell_offers_request)
            sell_offers = json.dumps(response.result, indent=4)

            all_offers = f"Buy Offers:\n{buy_offers}\n\nSell Offers:\n{sell_offers}"
            return render(request, 'nft_api/offers.html', {'offers': all_offers})
    
    
    
    form = NFTIdForm()
    accounts = XRPL_Model.objects.exclude(user_id=user_id).values('user__username', 'created_at')
    result = XRPL_Model.objects.filter(user_id=user_id).values_list('user__username', flat=True).first()
    if result:
        account_name = result
    else:
        account_name = None  # Handle the case when no result is found

    return render(request, 'nft_api/index.html', {'xrpl_data': xrpl_data,  'final_random_uri':final_random_uri, 'account_name':account_name, 'accounts':accounts, 'nft_uri_pairs': nft_uri_pairs, 'form':form, 'nft_length': nft_length})

def collections(request):
    if request.user.is_authenticated:
        user_id = request.user.id
        accounts = XRPL_Model.objects.exclude(user_id=user_id).values('user__username', 'created_at')
        p = Paginator(accounts, 5)
        # Create a Paginator instance
        page_number = request.GET.get('page')
        page_obj = p.get_page(page_number)
        context = {'page_obj': page_obj}



        return render(request, 'nft_api/collections.html', {'accounts': accounts,"context":context})
   
def explore(request):
    
    xrpl_data = None 
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass 

        initial_issuer_address = xrpl_data.account_address if xrpl_data else ""
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)
        issuerAddr = initial_issuer_address
        issuer = XRPL_Model.objects.get(account_address=issuerAddr)
        user_name = str(issuer.user)
        get_account_nfts = client.request(AccountNFTs(account=issuerAddr))
        nft_int = 1
        NFTs = []
        URI = []

        for nft in get_account_nfts.result['account_nfts']:
            encoded_uri = nft['URI']

            try:
                decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
            except UnicodeDecodeError:
                decoded_uri = "Invalid or non-UTF-8 data"
            
            NFTs.append(nft['NFTokenID'])
            URI.append("https://gateway.pinata.cloud/ipfs/" + decoded_uri)

            nft_int += 1

    NFTs = NFTs
    print("NFTs : ", NFTs)
    nft_length = len(NFTs)
    URI = URI
    nft_uri_pairs = zip(NFTs, URI)
    print("nft_uri_pairs : ", nft_uri_pairs)
    print("Issuer Address: ", issuerAddr)
    print("User Name : ", user_name)
    
    return render(request, 'nft_api/explore.html', {'NFTs':NFTs,  'nft_uri_pairs':nft_uri_pairs, 'nft_length':nft_length, 'issuerAddr':issuerAddr, 'user_name':user_name})



        

# def profile(request):
#     xrpl_data = None 
#     if request.user.is_authenticated:
#         user_id = request.user.id
#         try:
#             xrpl_data = XRPL_Model.objects.get(user_id=user_id)
#         except XRPL_Model.DoesNotExist:
#             pass  

#     return render(request, 'nft_api/index.html', {'xrpl_data': xrpl_data})


 

def generate_wallet_view(request):

    JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
    client = JsonRpcClient(JSON_RPC_URL)
    wallet = generate_faucet_wallet(client=client)
    context = {
        'wallet': wallet,
    }
    return render(request, 'nft_api/generate_wallet.html', context)


from pinata import Pinata
from django.core import serializers

def mint_nft_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    initial_seed = xrpl_data.seed if xrpl_data else ""  # Get the initial seed value

    if request.method == 'POST':
        print(xrpl_data)
        
        # Serialize the XRPL_Model data to JSON
        xrpl_data_json = serializers.serialize('json', [xrpl_data]) if xrpl_data else None
        
        form = NFTForm(request.POST, request.FILES, initial={'seed': initial_seed, 'xrpl_data': xrpl_data_json})
        if form.is_valid():
            title = form.cleaned_data['title']
            description = form.cleaned_data['description']
            image = form.cleaned_data['image']
            
            metadata = {
                "title": title,
                "description": description,
                "author": {
                    "username": xrpl_data_json,
                }
            }


            PINATA_API_KEY = "cf12813d69add8b9eaf3"
            PINATA_API_SECRET = "da8abf94b7e7ea7b954674ba1bf3892d05c8a0cc50ca766a0fdd7756e80bf2e5"

            PINATA_ENDPOINT = 'https://api.pinata.cloud/pinning/pinFileToIPFS'

            # Prepare the headers with your Pinata API key and secret
            headers = {
                'pinata_api_key': PINATA_API_KEY,
                'pinata_secret_api_key': PINATA_API_SECRET
            }

            # Prepare the payload (file)
            files = {'file': (image.name, image.read())}

            # Make the POST request to Pinata
            response = requests.post(PINATA_ENDPOINT, headers=headers, files=files, json=metadata)
            print(metadata)

            if response.status_code == 200:
                pinata_response = response.json()
                ipfs_cid = pinata_response['IpfsHash']
                print("IPFS CID:", ipfs_cid)
                # You can construct the URI like this:
                URI = "https://gateway.pinata.cloud/ipfs/" + ipfs_cid
                hex_value = ipfs_cid.encode('utf-8').hex()
                # decoded_string = hex_value.decode('utf-8')

            JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
            client = JsonRpcClient(JSON_RPC_URL)

            user_entered_seed = form.cleaned_data.get('seed')

            issuer_wallet = Wallet.from_seed(seed=user_entered_seed)
            issuerAddr = issuer_wallet.address

            mint_tx = NFTokenMint(
                account=issuerAddr,
                nftoken_taxon=1,
                flags=NFTokenMintFlag.TF_TRANSFERABLE,
                uri=hex_value,
            )

            taxon_value = mint_tx.nftoken_taxon

            print(taxon_value)

            mint_tx_response = submit_and_wait(transaction=mint_tx, client=client, wallet=issuer_wallet)
            mint_tx_result = mint_tx_response.result
            print(mint_tx_result)
            
            nftoken_id = mint_tx_result['meta']['nftoken_id']

            for node in mint_tx_result['meta']['AffectedNodes']:
                if "CreatedNode" in list(node.keys())[0]:
                    print(f"\n - NFT metadata:"
                        f"\n        NFT ID: {node['CreatedNode']['NewFields']['NFTokens'][0]['NFToken']['NFTokenID']}"
                        f"\n  Raw metadata: {node}")

                    
            # print(mint_tx_result.URI)
            # Query the minted account for its NFTs
            get_account_nfts = client.request(
                AccountNFTs(account=issuerAddr)
            )
            
            xrpl_data = json.loads(xrpl_data_json)
            title = metadata['title']
            description = metadata['description']
            author = xrpl_data[0]['fields']['account_address']
            time = xrpl_data[0]['fields']['created_at']

            nft_int = 0
            for nft in get_account_nfts.result['account_nfts']:
                nft_id = nft['NFTokenID']

                nft_int += 1
            
            context = {
                'nftoken_id': nftoken_id, 
                'URI': URI, 
                'ipfs_cid':ipfs_cid, 
                'title':title, 
                'description':description, 
                'author':author,
                'time':time,
                'taxon_value':taxon_value,
            }
                
            return render(request, 'nft_api/mint_success.html', context)
    else:
        form = NFTForm(initial={'seed': initial_seed})  # Set the initial value for the seed field

    return render(request, 'nft_api/mint_form.html', {'form': form, 'xrpl_data': xrpl_data})
testnet_url = "https://s.altnet.rippletest.net:51234"

def collections(request):
    if request.user.is_authenticated:
        user_id = request.user.id
        accounts = XRPL_Model.objects.exclude(user_id=user_id).values('user__username', 'account_address', 'created_at')
        accounts = list(accounts)
        account_addresses = [entry['account_address'] for entry in accounts]
        # print(account_addresses)
        p = Paginator(account_addresses, 5)
        # Create a Paginator instance
        page_number = request.GET.get('page')
        page_obj = p.get_page(page_number)
        nft_counts = []
        for initial_issuer_address in account_addresses:
            JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
            client = JsonRpcClient(JSON_RPC_URL)
            issuerAddr = initial_issuer_address
            get_account_nfts = client.request(AccountNFTs(account=issuerAddr))
            nft_count = len(get_account_nfts.result['account_nfts'])
            nft_counts.append(nft_count)

        print(nft_counts)

        context = {'page_obj': page_obj,}
        # print(nft_count_per_account)

    return render(request, 'nft_api/collections.html', {'accounts': accounts, "context": context,'nft_counts':nft_counts})

    
def All_nfts(request,account_address, nft_id=None):
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    issuer_address = xrpl_data.account_address if xrpl_data else ""

    issuer_address = account_address
    issuer = XRPL_Model.objects.get(account_address=issuer_address)
    created_at = issuer.created_at
    user_name = str(issuer.user)[:1]
    full_name = str(issuer.user)

    JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
    client = JsonRpcClient(JSON_RPC_URL)
    issuerAddr = issuer_address
    get_account_nfts = client.request(
        AccountNFTs(account=issuerAddr)
    )
    nft_int = 1
    NFTs = []
    URI = []

    for nft in get_account_nfts.result['account_nfts']:
        encoded_uri = nft['URI']
        # print('Account - NFT',get_account_nfts)
        try:
            decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
        except UnicodeDecodeError:
            # Handle the decoding error gracefully, e.g., by replacing invalid characters
            decoded_uri = "Invalid or non-UTF-8 data"
        
        NFTs.append(nft)
        URI.append("https://gateway.pinata.cloud/ipfs/" + (decoded_uri))
        nft_int += 1


    NFTs = NFTs

    nft_length = len(NFTs)
    URI = URI
    nft_uri_pairs = zip(NFTs, URI)


    matching_object = next((obj for obj in NFTs if obj["NFTokenID"] == nft_id), None)

    if matching_object:
        print("Matching object found:")
        NFTokenID = matching_object['NFTokenID']
        Flag = matching_object['Flags']
        Issuer = matching_object['Issuer']
        NFTokenTaxon = matching_object['NFTokenTaxon']
        got_uri = matching_object['URI']
        nft_serial = matching_object['nft_serial']

        encoded_uri = got_uri

        try:
            decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
            image = "https://gateway.pinata.cloud/ipfs/"+decoded_uri
            print(image)
        except UnicodeDecodeError:
            # Handle the decoding error gracefully, e.g., by replacing invalid characters
            decoded_uri = "Invalid or non-UTF-8 data"

        return render(request, 'nft_api/Account_NFTs.html',{'image':image,'NFTokenID':NFTokenID, 'Flag':Flag, 'Issuer':Issuer, 'NFTokenTaxon':NFTokenTaxon, 'decoded_uri':decoded_uri, 'nft_serial':nft_serial})

       
    return render(request, 'nft_api/collections_account_detail.html', {'NFTs': NFTs , 'full_name':full_name, 'nft_uri_pairs': nft_uri_pairs, 'nft_length': nft_length,"account_address": account_address,"nft_length":nft_length, "URI":URI,'created_at':created_at,'user_name':user_name})


def nft_detail(request, nft_id):
    if not request.user.is_authenticated:
        return redirect('login')

    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    issuer_address = xrpl_data.account_address if xrpl_data else ""

    JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
    client = JsonRpcClient(JSON_RPC_URL)
    issuerAddr = issuer_address
    get_account_nfts = client.request(AccountNFTs(account=issuerAddr))

    NFT_details = []

    for nft in get_account_nfts.result['account_nfts']:
        encoded_uri = nft['URI']

        try:
            decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
        except UnicodeDecodeError:
            decoded_uri = "Invalid or non-UTF-8 data"

        NFT_details.append({
            'NFT_ID': nft['NFTokenID'],
            'Owner': nft['Issuer'],
            'Issuer': issuer_address,
            'Taxon': nft['NFTokenTaxon'],
            'Serial': nft['nft_serial'],
            'Flag': 'transferable' if nft['Flags'] & 8 else 'non-transferable',
            'image': decoded_uri,
            'URI': "https://gateway.pinata.cloud/ipfs/" + (decoded_uri)
        })

    # Check if nft_id exists in NFTs
    for nft_detail in NFT_details:
        if nft_detail['NFT_ID'] == nft_id:
            # NFT details found, return them
            return render(request, 'nft_api/nft_detail.html', {'nft_detail': nft_detail})

    # If nft_id is not found, handle this case or provide an error message
    return render(request, 'nft_api/nft_not_found.html')
def create_sell_offer_view(request):
    if not request.user.is_authenticated:
        return redirect('login')

    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass
 
    initial_seed = xrpl_data.seed if xrpl_data else ""
    initial_issuer_address = xrpl_data.account_address if xrpl_data else ""
    
    if request.method == 'POST':
        form = SellOfferForm(request.POST, initial={'seed': initial_seed})
        if form.is_valid():
            amount = form.cleaned_data['amount']
            nftoken_id = form.cleaned_data['nftoken_id']
            # expiration = form.cleaned_data['expiration']

            user_entered_seed = form.cleaned_data.get('seed')
            owner_wallet = Wallet.from_seed(seed=user_entered_seed, algorithm="ed25519")
            client = JsonRpcClient(testnet_url)
            
            # try:
            #     expiration_date = datetime.now()
            #     if expiration:
            #         expiration_timedelta = timedelta(seconds=int(expiration))
            #         expiration_date = datetime.now() + expiration_timedelta
            #         expiration_date = xrpl.utils.datetime_to_ripple_time(expiration_date)
            # except OverflowError:
            #     return HttpResponseBadRequest("Invalid expiration date. Please enter a valid date.")

            sell_offer_tx = xrpl.models.transactions.NFTokenCreateOffer(
                account=owner_wallet.classic_address,
                nftoken_id=nftoken_id,
                amount=str(amount),
                # expiration=expiration_date if expiration else None,
                flags=1
            )
 
            response = submit_and_wait(sell_offer_tx, client, owner_wallet)
 
            # Assuming successful response (update with actual response check)
            if response:
                return render(request, 'nft_api/success_sell.html', {'sell_offer_tx': sell_offer_tx, 'client': client, 'owner_wallet':owner_wallet})
    else:
        form = SellOfferForm(initial={'seed': initial_seed})
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)
        issuerAddr = initial_issuer_address
        get_account_nfts = client.request(
            AccountNFTs(account=issuerAddr)
        )
        nft_int = 1
        NFTs = []
        URI =[]

        for nft in get_account_nfts.result['account_nfts']:

            encoded_uri = nft['URI']
    
            try:
                decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
            except UnicodeDecodeError:
                # Handle the decoding error gracefully, e.g., by replacing invalid characters
                decoded_uri = "Invalid or non-UTF-8 data"
            
            NFTs.append(nft['NFTokenID'])
            URI.append("https://gateway.pinata.cloud/ipfs/"+(decoded_uri))

            nft_int += 1

    NFTs = NFTs
    nft_length = len(NFTs)
    URI = URI
    nft_uri_pairs = zip(NFTs, URI)

    return render(request, 'nft_api/create_sell_offer.html', {'nft_uri_pairs': nft_uri_pairs, 'form':form, 'nft_length': nft_length},)

def accept_sell_offer_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    initial_seed = xrpl_data.seed if xrpl_data else ""
    if request.method == 'POST':
        offer_index = request.POST.get('offer_index')  # Assuming you send the offer_index as a POST parameter

        buyer_wallet = Wallet.from_seed(seed=initial_seed, algorithm="ed25519")
        client = JsonRpcClient(testnet_url)

        try:
            accept_offer_tx = xrpl.models.transactions.NFTokenAcceptOffer(
                account=buyer_wallet.classic_address,
                nftoken_sell_offer=offer_index
            )

            response = submit_and_wait(accept_offer_tx, client, buyer_wallet)

            return render(request, 'nft_api/success_accept_sell_offer.html', {'accept_offer_tx': accept_offer_tx})

        except Exception as e:
            error_message = str(e)
            if "tecEXPIRED" in error_message:
                # Transaction failed with tecEXPIRED, render the expired message
                return render(request, 'nft_api/sell_offer_expired.html')

    return render(request, 'nft_api/xrpl_accounts.html')


# Define your testnet_url
testnet_url = "https://s.altnet.rippletest.net:51234/"

def create_buy_offer_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    intial_account_address = xrpl_data.account_address if xrpl_data else ""
    # intial_issuer_address = xrpl_data.account_address if xrpl_data else ""  # Get the initial seed value

    if request.method == 'POST':
        form = BuyOfferForm(request.POST, request.FILES, initial={'owner': intial_account_address})
        if form.is_valid():
            # Handle the form submission for creating a buy offer
            seed = form.cleaned_data['seed']
            amount = form.cleaned_data['amount']
            nft_id = form.cleaned_data['nft_id']
            # owner = form.cleaned_data['owner']
            # expiration = form.cleaned_data['expiration']

            # Get the client
            buyer_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
            client = JsonRpcClient(testnet_url)
            # try:
            #     expiration_date = datetime.now()
            #     if expiration:
            #         expiration_timedelta = timedelta(seconds=int(expiration))
            #         expiration_date = datetime.now() + expiration_timedelta
            #         expiration_date = xrpl.utils.datetime_to_ripple_time(expiration_date)
            # except OverflowError:
            #     return HttpResponseBadRequest("Invalid expiration date. Please enter a valid date.")
            
            user_entered_owner = form.cleaned_data.get('owner')
            # Define the buy offer transaction with an expiration date
            buy_offer_tx = NFTokenCreateOffer(
                account=buyer_wallet.classic_address,
                nftoken_id=nft_id,
                amount=str(amount),
                owner=user_entered_owner,
                # expiration=expiration_date if expiration else None,
                flags=0
            )
            
            # Sign and fill the transaction
            response = submit_and_wait(buy_offer_tx, client, buyer_wallet)
            
            return render(request, 'nft_api/buy_offer_success.html', {'buy_offer_tx': buy_offer_tx})
    else:
        form = BuyOfferForm(initial={'owner': intial_account_address})

    # Code to retrieve XRPL accounts
    xrpl_accounts = XRPL_Model.objects.exclude(user_id=user_id).values('user__username', 'created_at', 'seed')


    # Code to retrieve NFTs
    JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
    client = JsonRpcClient(JSON_RPC_URL)
    issuerAddr = intial_account_address
    get_account_nfts = client.request(
        AccountNFTs(account=issuerAddr)
    )
    nft_int = 1
    NFTs = []
    URI = []

    for nft in get_account_nfts.result['account_nfts']:
        encoded_uri = nft['URI']
        try:
            decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
        except UnicodeDecodeError:
            decoded_uri = "Invalid or non-UTF-8 data"
        
        NFTs.append(nft['NFTokenID'])
        URI.append("https://gateway.pinata.cloud/ipfs/"+(decoded_uri))
        nft_int += 1
   
    NFTs = NFTs
    nft_length = len(NFTs)
    URI = URI
    nft_uri_pairs = zip(NFTs, URI)

    return render(request, 'nft_api/create_buy_offer.html', {'nft_uri_pairs': nft_uri_pairs, 'form':form, 'nft_length': nft_length,'xrpl_accounts': xrpl_accounts})



def get_offers_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass
 
    initial_issuer_address = xrpl_data.account_address if xrpl_data else ""
    if request.method == 'POST':
        form = NFTIdForm(request.POST)
        if form.is_valid():
            nft_id = form.cleaned_data['nft_id']
            
            client = JsonRpcClient(testnet_url)

            offers_request = NFTBuyOffers(nft_id=nft_id)
            response = client.request(offers_request)
            buy_offers = json.dumps(response.result, indent=4)

            sell_offers_request = NFTSellOffers(nft_id=nft_id)
            response = client.request(sell_offers_request)
            sell_offers = json.dumps(response.result, indent=4)

            all_offers = f"Buy Offers:\n{buy_offers}\n\nSell Offers:\n{sell_offers}"
            return render(request, 'nft_api/offers.html', {'offers': all_offers})
    else:
        form = NFTIdForm()
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)
        issuerAddr = initial_issuer_address
        get_account_nfts = client.request(
            AccountNFTs(account=issuerAddr)
        )
        nft_int = 1
        NFTs = []
        URI =[]

        for nft in get_account_nfts.result['account_nfts']:

            encoded_uri = nft['URI']
    
            try:
                decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
            except UnicodeDecodeError:
                # Handle the decoding error gracefully, e.g., by replacing invalid characters
                decoded_uri = "Invalid or non-UTF-8 data"
            
            NFTs.append(nft['NFTokenID'])
            URI.append("https://gateway.pinata.cloud/ipfs/"+(decoded_uri))

            nft_int += 1

    NFTs = NFTs
    URI = URI

    return render(request, 'nft_api/get_offers_form.html', {'form': form, 'NFTs':NFTs, 'URI':URI},)

    # return render(request, 'nft_api/get_offers_form.html', {'form': form})


def xrpl_accounts(request):
    if not request.user.is_authenticated:
        return redirect('login')

    xrpl_accountss = XRPL_Model.objects.exclude(user=request.user)
    xrpl_accountss = list(reversed(xrpl_accountss))

    offers_data = []  # List to store both sell and buy offers for each account holder

    # Iterate through XRPL accounts
    for xrpl_account in xrpl_accountss:
        # Assuming 'account_address' is the attribute name in your User model for XRPL account addresses
        account_address = xrpl_account.account_address

        # Connect to a testnet node
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)

        # Query for NFTs associated with the account
        account_nfts = client.request(AccountNFTs(account=account_address))
        nfts = account_nfts.result.get('account_nfts', [])

        nft_data = []  # List to store NFTs with their sell and buy offers

        has_sell_offers = False
        has_buy_offers = False

        for nft in nfts:
            nft_id = nft['NFTokenID']

            # Query for sell offers associated with the NFT
            sell_offers = client.request(NFTSellOffers(nft_id=nft_id))
            sell_offer_objects = sell_offers.result.get('offers', [])

            # Query for buy offers associated with the NFT
            buy_offers = client.request(NFTBuyOffers(nft_id=nft_id))
            buy_offer_objects = buy_offers.result.get('offers', [])

            nft_info = {
                'nft_id': nft_id,
                'sell_offers': sell_offer_objects,
                'buy_offers': buy_offer_objects,
            }

            nft_data.append(nft_info)

            # Check if there are sell or buy offers for this account
            if sell_offer_objects:
                has_sell_offers = True
            if buy_offer_objects:
                has_buy_offers = True

        offers_data.append({'account': xrpl_account, 'nfts': nft_data, 'has_sell_offers': has_sell_offers, 'has_buy_offers': has_buy_offers})

    context = {'xrpl_accounts': xrpl_accountss, 'offers_data': offers_data}

    # Render a template to display the data
    return render(request, 'nft_api/xrpl_accounts.html', context)


def accept_buy_offer_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass

    seed = xrpl_data.seed if xrpl_data else ""

    if request.method == 'POST':
        form = AcceptBuyOfferForm(request.POST)
        if form.is_valid():
            JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
            client = JsonRpcClient(JSON_RPC_URL)

            seed = form.cleaned_data.get('seed')
            offer_index = form.cleaned_data['offer_index']

            try:

                buyer_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
                client = JsonRpcClient(testnet_url)

                accept_offer_tx = NFTokenAcceptOffer(
                    account=buyer_wallet.classic_address,
                    nftoken_buy_offer=offer_index
                )

                # Sign and fill the transaction
                response = submit_and_wait(accept_offer_tx, client, buyer_wallet)

                return render(request, 'nft_api/accept_buy_offer_success.html', {'accept_offer_tx': accept_offer_tx})
            except Exception as e:
                error_message = str(e)
                if "tecEXPIRED" in error_message:
                    return render(request, 'nft_api/buy_offer_expired.html')

    else:
        form = AcceptBuyOfferForm()
        xrpl_accounts = XRPL_Model.objects.exclude(user=request.user)

        # Get the classic address associated with the seed
        json_rpc_url = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(json_rpc_url)

        # Replace 'your_seed_here' with the actual seed you want to query
        # seed = "sEdTYeQdPTnvrymNRGL7LNq7hGnFHpf"

        # Get the classic address associated with the seed
        wallet = Wallet.from_seed(seed=seed)
        classic_address = wallet.classic_address

        # Define the request to fetch account objects
        account_objects_request = AccountObjects(account=classic_address)

        # Send the request to the XRPL node
        response = client.request(account_objects_request)

        # Extract the offers from the response
        account_objects = response.result.get("account_objects", [])


        # Extract 'PreviousTxnID', 'index', 'Owner', 'Amount', and 'Expiration' from "NFTokenOffer" entries
        nft_offer_data = []
        for obj in account_objects:
            if obj.get("LedgerEntryType") == "NFTokenOffer":
                # previous_txn_id = obj.get("PreviousTxnID")
                offer_index = obj.get("index")
                owner = obj.get("Owner")
                amount = obj.get("Amount")
                expiration = obj.get("Expiration")
                nft_offer_data.append({
                    # "PreviousTxnID": previous_txn_id,
                    "index": offer_index,
                    "Owner": owner,
                    "Amount": amount,
                    "Expiration": expiration
                })
        context = {'form': form, 'nft_offer_data': nft_offer_data, 'xrpl_accounts':xrpl_accounts}
        return render(request, "nft_api/buyer_data.html", context)

def find_nfts(request):

    if not request.user.is_authenticated:
        return redirect('login')
    xrpl_data = None
    if request.user.is_authenticated:
        user_id = request.user.id
        try:
            xrpl_data = XRPL_Model.objects.get(user_id=user_id)
        except XRPL_Model.DoesNotExist:
            pass
    if request.method == 'POST':
        seed = request.POST.get('seed')
        print(seed)

        # Initialize wallet from seed
        issuer_wallet = Wallet.from_seed(seed=seed)
        issuer_addr = issuer_wallet.address
        print(issuer_addr)

        # Connect to a testnet node
        JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
        client = JsonRpcClient(JSON_RPC_URL)

        # Query the issuer account for its NFTs
        get_account_nfts = client.request(AccountNFTs(account=issuer_addr))
        nfts = get_account_nfts.result.get('account_nfts', [])

        nft_list = []
        current_user_address = xrpl_data.account_address  # Replace 'address' with the actual attribute name in your User model

        for nft_data in nfts:
            nft_id = nft_data['NFTokenID']
            issuer = nft_data['Issuer']
            taxon = nft_data['NFTokenTaxon']

            sell_offers = client.request(NFTSellOffers(nft_id=nft_id))
            sell_offer_objects = sell_offers.result.get('offers', [])

            
            buy_offers = client.request(NFTBuyOffers(nft_id=nft_id))
            buy_offer_objects = buy_offers.result.get('offers', [])


            if sell_offer_objects or buy_offer_objects:
                nft_info = {
                    'nft_id': nft_id,
                    'issuer': issuer,
                    'taxon': taxon,
                    'sell_offers': sell_offer_objects,
                    'buy_offers': buy_offer_objects,
                }

                # Retrieve the URI for the NFT
                encoded_uri = nft_data['URI']
                try:
                    decoded_uri = binascii.unhexlify(encoded_uri).decode('utf-8')
                    nft_info['image_url'] = "https://gateway.pinata.cloud/ipfs/" + decoded_uri
                except UnicodeDecodeError:
                    # Handle the decoding error gracefully, e.g., by setting a default image URL
                    nft_info['image_url'] = "https://static.thenounproject.com/png/3482632-200.png"
                
                nft_list.append(nft_info)
        print(nft_list)

                # for buy_offer in buy_offer_objects:
                #     buyer_address = buy_offer.get('owner')  # Replace 'buyer' with the actual attribute name in your buy offer object
                #     print(f"Buyer address: {buyer_address}")
                #     if current_user_address == buyer_address:
                #         print(f"Current user ({current_user_address}) is the owner of this buy offer.")

        return render(request, 'nft_api/find_nfts.html', {'nft_list': nft_list, 'xrpl_data': xrpl_data, 'seed': seed})
def cancel_offer_view(request):
    form = CancelOfferForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        seed = form.cleaned_data['seed']
        offer_id = form.cleaned_data['offer_id']  # Get the offer ID from the form

        owner_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
        client = JsonRpcClient(testnet_url)

        token_offer_ids = [offer_id]  # Use the provided offer ID

        cancel_offer_tx = NFTokenCancelOffer(
            account=owner_wallet.classic_address,
            nftoken_offers=token_offer_ids
        )

        response = submit_and_wait(cancel_offer_tx, client, owner_wallet)

        return render(request, 'nft_api/cancel_offer_success.html', {'response': response, 'offer_id': offer_id})

    return render(request, 'nft_api/cancel_offer.html', {'cancel_offer_form': form})


def broker_sale_view(request):
    error_message = None  # Initialize error_message as None

    if request.method == 'POST':
        form = BrokerSaleForm(request.POST)
        if form.is_valid():
            # Get cleaned data from the form
            seed = form.cleaned_data['seed']
            sell_offer_index = form.cleaned_data['sell_offer_index']
            buy_offer_index = form.cleaned_data['buy_offer_index']
            broker_fee = form.cleaned_data['broker_fee']

            try:

                broker_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
                client = JsonRpcClient(testnet_url)

                # Create and send the XRPL transaction
                accept_offer_tx = xrpl.models.transactions.NFTokenAcceptOffer(
                    account=broker_wallet.classic_address,
                    nftoken_sell_offer=sell_offer_index,
                    nftoken_buy_offer=buy_offer_index,
                    nftoken_broker_fee=broker_fee
                )
                response = submit_and_wait(accept_offer_tx, client, broker_wallet)
                reply = response.result

                if "Successful" in reply:
                    # If the response contains "Successful", render the success template
                    return render(request, 'nft_api/broker_sale_success.html')
                else:
                    # Set error_message to the error message
                    error_message = f"Broker Sale Failed: {reply}"
            except Exception as e:
                # Handle any exceptions that occur during the XRPL transaction
                error_message = f"An error occurred: {str(e)}"
        else:
            # If the form is not valid, display an error message
            error_message = "Form is not valid. Please check your input."
    else:
        # Display the form for user input
        form = BrokerSaleForm()

    return render(request, 'nft_api/broker_sale_form.html', {'form': form, 'error_message': error_message})


def set_minter_view(request):
    if request.method == 'POST':
        form = SetMinterForm(request.POST)

        if form.is_valid():
            seed = form.cleaned_data['seed']
            minter = form.cleaned_data['minter']

            granter_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
            client = JsonRpcClient(testnet_url)

            set_minter_tx=xrpl.models.transactions.AccountSet(
                    account=granter_wallet.classic_address,
                    nftoken_minter=minter,
                    set_flag=xrpl.models.transactions.AccountSetAsfFlag.ASF_AUTHORIZED_NFTOKEN_MINTER,
                )     

            # Sign and fill the transaction
            response = submit_and_wait(set_minter_tx, client, granter_wallet)

            return render(request, 'nft_api/set_minter_success.html', {'response': response})

    else:
        form = SetMinterForm()

    return render(request, 'nft_api/set_minter.html', {'form': form})

def mint_other_view(request):
    if request.method == 'POST':
        form = MintOtherForm(request.POST)

        if form.is_valid():
            seed = form.cleaned_data['seed']
            uri = form.cleaned_data['uri']
            flags = form.cleaned_data['flags']
            transfer_fee = form.cleaned_data['transfer_fee']
            taxon = form.cleaned_data['taxon']
            issuer = form.cleaned_data['issuer']

            minter_wallet = Wallet.from_seed(seed=seed, algorithm="ed25519")
            client = JsonRpcClient(testnet_url)

            mint_other_tx=xrpl.models.transactions.NFTokenMint(
                account=minter_wallet.classic_address,
                uri=xrpl.utils.str_to_hex(uri),
                flags=int(flags),
                transfer_fee=int(transfer_fee),
                nftoken_taxon=int(taxon),
                issuer=issuer
            )

            # Sign and fill the transaction
            response = submit_and_wait(mint_other_tx, client, minter_wallet)

            return render(request, 'nft_api/mint_other_success.html', {'response': response})

    else:
        form = MintOtherForm()

    return render(request, 'nft_api/mint_other.html', {'form': form})



# Callback URL specified when initiating the sign-in request
REDIRECT_URI = "http://127.0.0.1:8000/xumm/callback"
# Xumm token endpoint URL (you need to verify this with Xumm's API documentation)
TOKEN_URL = "https://xumm.app/oauth2/token"

class XummView(View):
    def dispatch(self, request, *args, **kwargs):
        return self.handle_xumm_request(request)

    def handle_xumm_request(self, request):
        xumm_api_key = "a8735a41-7485-4e88-9058-32b6ef2d199c"
        xumm_secret_key = "0e876a4e-e8eb-4a0c-9f9d-7cd7aa1b4def"

        # Create a payload using the provided JSON data
        payload_data = {
            "txjson": {
               "TransactionType": "SignIn"
            },
            "options": {
                "return_url": {
                "web": " http://127.0.0.1:8000/xumm_callback"
                }
            }
        }
        payload_url = "https://xumm.app/api/v1/platform/payload"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": xumm_api_key,
            "X-API-Secret": xumm_secret_key,
        }

        payload_response = requests.post(
            payload_url, headers=headers, data=json.dumps(payload_data)
        )

        payload_result = payload_response.json()
        print("payload", payload_result)

        uuid = payload_result.get("uuid")

        # Store the UUID in the session
        request.session["xumm_uuid"] = payload_result["uuid"]

        # Check if Xumm verification is successful
        if uuid:
            # Redirect the user to the Xumm verification page
            xumm_verification_url = payload_result["next"]["always"]
            print(xumm_verification_url)
            print(payload_result)
            return HttpResponseRedirect(xumm_verification_url)
        
        # Check if the transaction success
        if payload_result.get("error") is None:
            return JsonResponse({"message": "Sign-in transaction successful"})
        else:
            # Sign-in transaction failed
            return JsonResponse({"error": "Xumm payload creation failed."})

from django.shortcuts import HttpResponse

class XummCallbackView(View):
    def get(self, request):
        # Retrieve the XUMM UUID from the session
        xumm_uuid = request.session.get("xumm_uuid")
        print(xumm_uuid)

        if xumm_uuid:
            # Query the XUMM API to get account details based on the UUID
            xumm_api_key = "a8735a41-7485-4e88-9058-32b6ef2d199c"
            xumm_secret_key = "0e876a4e-e8eb-4a0c-9f9d-7cd7aa1b4def"

            account_details_url = f"https://xumm.app/api/v1/platform/payload/{xumm_uuid}"
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": xumm_api_key,
                "X-API-Secret": xumm_secret_key,
            }

            account_response = requests.get(account_details_url, headers=headers)

            if account_response.status_code == 200:
                account_data = account_response.json()
                account = account_data["response"]["account"]
                # Store the account value in the session
                request.session["xumm_account"] = account
                context = {'account':account}
                print("Account:", account)
                # Process and use the account data as needed
                # For example, you can display it on your website or store it in your database
                return render(request, 'nft_api/index.html', context)
            else:
                return HttpResponse("Failed to retrieve XUMM account details.")
        else:
            return HttpResponse("No XUMM UUID found in the session.")