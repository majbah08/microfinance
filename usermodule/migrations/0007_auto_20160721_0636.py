# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-21 06:36
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('usermodule', '0006_auto_20160721_0625'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usersecuritycode',
            name='generation_time',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
    ]
