# Generated by Django 2.1.2 on 2019-08-23 14:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_wallet'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='wallet',
            name='endpoint',
        ),
    ]
