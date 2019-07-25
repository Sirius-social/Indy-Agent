from django.db import models


class StartedStateMachine(models.Model):
    machine_id = models.CharField(max_length=512, primary_key=True)
    machine_class_name = models.CharField(max_length=512)
