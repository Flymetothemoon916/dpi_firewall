from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q

from .models import RuleCategory, Rule, IPBlacklist, IPWhitelist
from .forms import RuleForm, IPBlacklistForm, IPWhitelistForm

@login_required
def rule_list(request):
    """显示规则列表页面"""
    rules = Rule.objects.all()
    
    # 筛选条件
    search_query = request.GET.get('q', '')
    category_filter = request.GET.get('category', '')
    status_filter = request.GET.get('status', '')
    action_filter = request.GET.get('action', '')
    
    if search_query:
        rules = rules.filter(
            Q(name__icontains=search_query) | 
            Q(description__icontains=search_query) |
            Q(source_ip__icontains=search_query) | 
            Q(destination_ip__icontains=search_query)
        )
    
    if category_filter:
        rules = rules.filter(category__id=category_filter)
    
    if status_filter:
        is_enabled = status_filter == 'enabled'
        rules = rules.filter(is_enabled=is_enabled)
    
    if action_filter:
        rules = rules.filter(action=action_filter)
    
    # 分页
    paginator = Paginator(rules, 20)  # 每页显示20条
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # 获取分类列表用于筛选
    categories = RuleCategory.objects.all()
    
    context = {
        'page_obj': page_obj,
        'categories': categories,
        'search_query': search_query,
        'category_filter': category_filter,
        'status_filter': status_filter,
        'action_filter': action_filter,
    }
    
    return render(request, 'firewall_rules/rule_list.html', context)


@login_required
def rule_detail(request, rule_id):
    """显示规则详情页面"""
    rule = get_object_or_404(Rule, id=rule_id)
    return render(request, 'firewall_rules/rule_detail.html', {'rule': rule})


@login_required
def rule_create(request):
    """创建新规则页面"""
    if request.method == 'POST':
        form = RuleForm(request.POST)
        if form.is_valid():
            rule = form.save()
            messages.success(request, f'规则 "{rule.name}" 创建成功')
            return redirect('rule_detail', rule_id=rule.id)
    else:
        form = RuleForm()
    
    return render(request, 'firewall_rules/rule_form.html', {'form': form, 'title': '创建规则'})


@login_required
def rule_edit(request, rule_id):
    """编辑规则页面"""
    rule = get_object_or_404(Rule, id=rule_id)
    
    if request.method == 'POST':
        form = RuleForm(request.POST, instance=rule)
        if form.is_valid():
            rule = form.save()
            messages.success(request, f'规则 "{rule.name}" 更新成功')
            return redirect('rule_detail', rule_id=rule.id)
    else:
        form = RuleForm(instance=rule)
    
    return render(request, 'firewall_rules/rule_form.html', {'form': form, 'rule': rule, 'title': '编辑规则'})


@login_required
def rule_toggle(request, rule_id):
    """切换规则启用/禁用状态"""
    rule = get_object_or_404(Rule, id=rule_id)
    rule.is_enabled = not rule.is_enabled
    rule.save()
    
    status = '启用' if rule.is_enabled else '禁用'
    return JsonResponse({
        'status': 'success', 
        'enabled': rule.is_enabled,
        'message': f'规则 "{rule.name}" 已{status}'
    })


@login_required
def blacklist(request):
    """IP黑名单管理页面"""
    ips = IPBlacklist.objects.all().order_by('-added_at')
    
    if request.method == 'POST':
        form = IPBlacklistForm(request.POST)
        if form.is_valid():
            ip = form.save()
            messages.success(request, f'IP {ip.ip_address} 已添加到黑名单')
            return redirect('blacklist')
    else:
        form = IPBlacklistForm()
    
    return render(request, 'firewall_rules/blacklist.html', {'ips': ips, 'form': form})


@login_required
def blacklist_delete(request, ip_id):
    """从黑名单删除IP"""
    ip = get_object_or_404(IPBlacklist, id=ip_id)
    address = ip.ip_address
    ip.delete()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'status': 'success',
            'message': f'IP {address} 已从黑名单移除'
        })
    else:
        messages.success(request, f'IP {address} 已从黑名单移除')
        return redirect('blacklist')


@login_required
def whitelist(request):
    """IP白名单管理页面"""
    ips = IPWhitelist.objects.all().order_by('ip_address')
    
    if request.method == 'POST':
        form = IPWhitelistForm(request.POST)
        if form.is_valid():
            ip = form.save()
            messages.success(request, f'IP {ip.ip_address} 已添加到白名单')
            return redirect('whitelist')
    else:
        form = IPWhitelistForm()
    
    return render(request, 'firewall_rules/whitelist.html', {'ips': ips, 'form': form})


@login_required
def whitelist_delete(request, ip_id):
    """从白名单删除IP"""
    ip = get_object_or_404(IPWhitelist, id=ip_id)
    address = ip.ip_address
    ip.delete()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'status': 'success',
            'message': f'IP {address} 已从白名单移除'
        })
    else:
        messages.success(request, f'IP {address} 已从白名单移除')
        return redirect('whitelist')
