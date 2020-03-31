# Generated by Django 2.1.11 on 2020-03-31 18:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transport', '0014_invitation_connection_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitation',
            name='my_did',
            field=models.CharField(db_index=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='invitation',
            name='seed',
            field=models.CharField(db_index=True, max_length=128, null=True),
        ),
    ]
