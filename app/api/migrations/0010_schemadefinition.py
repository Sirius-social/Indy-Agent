# Generated by Django 2.1.2 on 2019-10-15 15:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_auto_20190826_1337'),
    ]

    operations = [
        migrations.CreateModel(
            name='SchemaDefinition',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('json', models.CharField(max_length=2056)),
            ],
        ),
    ]
