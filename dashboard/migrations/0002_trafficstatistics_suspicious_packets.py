# Generated by Django 4.2.7 on 2025-04-26 08:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='trafficstatistics',
            name='suspicious_packets',
            field=models.IntegerField(default=0, verbose_name='可疑数据包数'),
        ),
    ]
