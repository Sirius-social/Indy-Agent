# Generated by Django 2.1.2 on 2019-07-22 08:10

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('transport', '0004_auto_20190722_0805'),
    ]

    operations = [
        migrations.CreateModel(
            name='EntrypointDescriptor',
            fields=[
                ('id', models.CharField(max_length=2083, primary_key=True, serialize=False)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='entrypoints', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
