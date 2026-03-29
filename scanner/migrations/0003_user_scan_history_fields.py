from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def assign_existing_scanlogs_to_first_user(apps, schema_editor):
    ScanLog = apps.get_model('scanner', 'ScanLog')
    User = apps.get_model(settings.AUTH_USER_MODEL.split('.')[0], settings.AUTH_USER_MODEL.split('.')[1])
    first_user = User.objects.order_by('id').first()
    if first_user:
        ScanLog.objects.filter(user__isnull=True).update(user=first_user)


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('scanner', '0002_alter_scanlog_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanlog',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='scan_logs', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='target_label',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='status',
            field=models.CharField(default='completed', max_length=32),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='risk_score',
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='open_port_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='critical_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='scanlog',
            name='os_detected',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AlterField(
            model_name='scanlog',
            name='target_ip',
            field=models.CharField(max_length=45),
        ),
        migrations.RunPython(assign_existing_scanlogs_to_first_user, migrations.RunPython.noop),
    ]