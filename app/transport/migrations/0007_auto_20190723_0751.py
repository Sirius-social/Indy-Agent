# Generated by Django 2.1.2 on 2019-07-23 07:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('state_machines', '0002_remove_statemachine_transport'),
        ('transport', '0006_auto_20190722_0812'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='entrypointdescriptor',
            name='owner',
        ),
        migrations.AlterUniqueTogether(
            name='transportdescriptor',
            unique_together=set(),
        ),
        migrations.RemoveField(
            model_name='transportdescriptor',
            name='entrypoint',
        ),
        migrations.DeleteModel(
            name='EntrypointDescriptor',
        ),
        migrations.DeleteModel(
            name='TransportDescriptor',
        ),
    ]