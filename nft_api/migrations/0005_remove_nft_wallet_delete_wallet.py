# Generated by Django 4.1.3 on 2023-09-06 12:21

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('nft_api', '0004_wallet_nft_wallet'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='nft',
            name='wallet',
        ),
        migrations.DeleteModel(
            name='Wallet',
        ),
    ]
