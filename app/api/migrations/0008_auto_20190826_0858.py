# Generated by Django 2.1.2 on 2019-08-26 08:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_auto_20190826_0852'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='connection',
            name='owner',
        ),
        migrations.RemoveField(
            model_name='connection',
            name='wallet',
        ),
        migrations.DeleteModel(
            name='Connection',
        ),
    ]
