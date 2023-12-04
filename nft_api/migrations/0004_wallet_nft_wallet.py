# Generated by Django 4.1.3 on 2023-09-06 11:58

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('nft_api', '0003_alter_xrpl_model_user_id_delete_customuser'),
    ]

    operations = [
        migrations.CreateModel(
            name='Wallet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=100)),
                ('seed', models.CharField(max_length=100)),
            ],
        ),
        migrations.AddField(
            model_name='nft',
            name='wallet',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='nft_api.wallet'),
            preserve_default=False,
        ),
    ]