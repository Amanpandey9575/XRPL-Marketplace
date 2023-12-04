# Generated by Django 4.0.6 on 2023-09-06 04:32

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('nft_api', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='XRPL_Model',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('account_address', models.CharField(max_length=100)),
                ('seed', models.CharField(max_length=100)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='nft_api.customuser')),
            ],
        ),
    ]
