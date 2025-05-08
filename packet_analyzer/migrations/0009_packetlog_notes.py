from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packet_analyzer', '0008_packetlog_is_important_packetlog_is_read'),
    ]

    operations = [
        migrations.AddField(
            model_name='packetlog',
            name='notes',
            field=models.TextField(blank=True, verbose_name='备注'),
        ),
    ] 