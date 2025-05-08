from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packet_analyzer', '0009_packetlog_notes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='packetlog',
            name='processing_time',
            field=models.FloatField(default=0.0, verbose_name='处理时间(毫秒)'),
        ),
    ] 