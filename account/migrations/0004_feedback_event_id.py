# Generated by Django 3.0.2 on 2021-03-19 08:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('event', '0001_initial'),
        ('account', '0003_auto_20210318_0635'),
    ]

    operations = [
        migrations.AddField(
            model_name='feedback',
            name='event_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to='event.EventRecord'),
        ),
    ]
