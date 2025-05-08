from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packet_analyzer', '0007_merge_20250507_1939'),  # 修改依赖为最新的正确迁移
    ]

    operations = [
        migrations.AddField(
            model_name='packetlog',
            name='is_important',
            field=models.BooleanField(default=False, verbose_name='是否重要'),
        ),
        migrations.AddField(
            model_name='packetlog',
            name='is_read',
            field=models.BooleanField(default=False, verbose_name='是否已读'),
        ),
    ] 