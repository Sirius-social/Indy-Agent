# Generated by Django 2.1.2 on 2019-10-16 09:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_credentialdefinition'),
    ]

    operations = [
        migrations.AddField(
            model_name='credentialdefinition',
            name='did',
            field=models.CharField(db_index=True, max_length=512, null=True),
        ),
        migrations.AddField(
            model_name='credentialdefinition',
            name='schema',
            field=models.CharField(db_index=True, max_length=2056, null=True),
        ),
        migrations.AddField(
            model_name='credentialdefinition',
            name='wallet',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api.Wallet'),
        ),
    ]
