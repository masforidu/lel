# Generated by Django 5.1.1 on 2024-10-21 16:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shegarland', '0013_alter_shegarlandform_mallattoo_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shegarlandform',
            name='suura_iddoo',
            field=models.ImageField(upload_to='images/'),
        ),
    ]
