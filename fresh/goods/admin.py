from django.contrib import admin
from goods.models import *


class IndexGoodsBannerAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        '''新增或者更新表中的数据时调用'''
        super().save_model(request, obj, form, change)
        # 发出任务，让celery worker重新生成首页静态页
        from celery_tasks.tasks import generate_static_index_html
        generate_static_index_html.delay()

    def delete_model(self, request, obj):
        '''删除表中的数据时调用'''
        super().delete_model(request, obj)
        # 发出任务，让celery worker重新生成首页静态页
        from celery_tasks.tasks import generate_static_index_html
        generate_static_index_html.delay()


admin.site.register(GoodsType)
admin.site.register(Goods)
admin.site.register(GoodsSKU)
admin.site.register(GoodsImage)
admin.site.register(IndexTypeGoodsBanner)
admin.site.register(IndexPromotionBanner)
admin.site.register(IndexGoodsBanner)
