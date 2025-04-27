from django import forms
from .models import Rule, IPBlacklist, IPWhitelist, RulePattern

class RuleForm(forms.ModelForm):
    """防火墙规则表单"""
    pattern = forms.ModelMultipleChoiceField(
        queryset=RulePattern.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text='选择要匹配的模式'
    )
    
    class Meta:
        model = Rule
        fields = [
            'name', 'description', 'category', 'source_ip', 'destination_ip',
            'source_port', 'destination_port', 'protocol', 'pattern',
            'application_protocol', 'action', 'priority', 'log_prefix', 'is_enabled'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'log_prefix': forms.TextInput(),
        }


class IPBlacklistForm(forms.ModelForm):
    """IP黑名单表单"""
    class Meta:
        model = IPBlacklist
        fields = ['ip_address', 'description', 'expiry', 'is_permanent']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
            'expiry': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }


class IPWhitelistForm(forms.ModelForm):
    """IP白名单表单"""
    class Meta:
        model = IPWhitelist
        fields = ['ip_address', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
        } 