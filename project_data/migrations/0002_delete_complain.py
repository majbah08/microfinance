# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-18 10:50
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('project_data', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Complain',
        ),
    ]