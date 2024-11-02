# Generated by Django 5.1.1 on 2024-10-26 18:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shegarland', '0018_alter_shegarlandform_aanaa_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='shegarlandform',
            old_name='suura_iddoo',
            new_name='Ragaa_biroo',
        ),
        migrations.AlterField(
            model_name='shegarlandform',
            name='Mallattoo',
            field=models.ImageField(blank=True, null=True, upload_to='images/'),
        ),
        migrations.AlterField(
            model_name='shegarlandform',
            name='aanaa',
            field=models.CharField(choices=[('Abbaa Gadaa', 'Abbaa Gadaa'), ('wasarbii', 'wasarbii'), ('Tufaa munaa', 'Tufaa munaa'), ('A/M/Abbichuu', 'A/M/Abbichuu'), ('Eekkaa Daallee', 'Eekkaa Daallee'), ('Lagaa Dambal', 'Lagaa Dambal'), ('Ekkaa Sadeen', 'Ekkaa Sadeen'), ('Haroo Qullit', 'Haroo Qullit'), ('Dire_Sokkoruu', 'Dire Sokorruu'), ('Kuraa Jidda', 'Kuraa Jidda'), ('Galaan Arabsaa', 'Galaan Arabsaa'), ('Galaan Goraa', 'Galaan Goraa'), ('Faccee', 'Faccee'), ('Siidaa awaash', 'Siidaa awaash'), ('Galaan', 'Galaan'), ('Andoodee', 'Andoodee'), ('Mudaa Furii', 'Mudaa Furii'), ('Caffe karaabuu', 'Caffe karaabuu'), ('Gadaa Faajjii', 'Gadaa Faajjii'), ('Galaan Guddaa', 'Galaan Guddaa'), ('Lakkulee gejjaa', 'Lakkulee gejjaa'), ('Daalattii', 'Daalattii'), ('Wacacaa', 'Wacacaa'), ('Mogolee', 'Mogolee'), ('Caffee', 'Caffee'), ('M/gafarsaa', 'M/gafarsaa'), ('Nonnoo', 'Nonnoo'), ('Beeroo', 'Beeroo'), ('B/Kattaa', 'B/Kattaa'), ('L/kattaa', 'L/kattaa'), ('A/diimaa', 'A/diimaa'), ('G/burrayyuu', 'G/burrayyuu'), ('Egduu ilalaa', 'Egduu ilalaa'), ('Gujee', 'Gujee'), ('Koloboo', 'Koloboo')], max_length=50),
        ),
        migrations.AlterField(
            model_name='shegarlandform',
            name='magaalaa',
            field=models.CharField(choices=[('Sululta', 'Sululta'), ('M/abbichuu', 'M/abbichuu'), ('LXLD', 'LXLD'), ('K/Jiddaa', 'K/Jiddaa'), ('K/faccee', 'K/faccee'), ('Galaan', 'Galaan'), ('Furii', 'Furii'), ('G/Guddaa', 'G/Guddaa'), ('Sabbataa', 'Sabbataa'), ('M/Nonnoo', 'M/Nonnoo'), ('G/Gujee', 'G/Gujee'), ('Burrayyu', 'Burrayyu')], max_length=50),
        ),
        migrations.AlterField(
            model_name='shegarlandform',
            name='tajajila_qophaef',
            field=models.CharField(choices=[('Bankii Lafa', 'Bankii Lafa'), ('Mana jirenya', 'Mana jirenya'), ('Daldala', 'Daldala'), ('Tajajilaa Bulchi', 'Tajajilaa Bulchi'), ('Tajajilaa Haw.', 'Tajajilaa Haw.'), ('Investimenti', 'Investimenti'), ('IMX', 'IMX'), ('Magarisumma', 'Magarisumma'), ('Innishetivif', 'Innishetivif'), ('Tajajila babalifanna', 'Tajajila babalifanna'), ('Qonnaa', 'Qonnaa'), ('Tajajila yeroof', 'Tajajila yeroof'), ('Tajaajila Babal', 'Tajaajila Babal')], max_length=50),
        ),
    ]
