from django.db import models
from django.contrib.auth.models import User
from project_data.helpers import send_push_msg
from django.utils import timezone
import datetime
import pytz
# Create your models here.
class Complain(models.Model):
    account_no = models.CharField(max_length=100, null=True)
    service_type = models.CharField(max_length=100, null=True)
    customer_name = models.CharField(max_length=100, null=True)
    balance = models.CharField(max_length=100, null=True)
    id_type = models.CharField(max_length=100, null=True)
    id_no = models.CharField(max_length=100, null=True)
    transaction_id = models.CharField(max_length=100, null=True)
    transaction_date_time = models.DateTimeField(null=True)
    lock_date_time = models.DateTimeField(null=True)
    transaction_amount = models.CharField(max_length=100, null=True)
    remarks_of_csa_customer = models.CharField(max_length=400, null=True)
    remarks_of_bkash_cs = models.CharField(max_length=400, null=True, blank=True)
    execution_status = models.CharField(max_length=100, null=True)
    not_execute_reason = models.CharField(max_length=100, null=True, blank=True)
    pin = models.ForeignKey(User,related_name='user_pin', on_delete=models.PROTECT)
    received_time = models.DateTimeField(default = datetime.datetime.now, blank=True) # was previously timezone.now
    locker = models.ForeignKey(User,related_name='locker_agent', on_delete=models.SET_NULL, null=True)
    
    __original_execution_status = None
    def __init__(self, *args, **kwargs):
        super(Complain, self).__init__(*args, **kwargs)
        self.__original_execution_status = self.execution_status

    def save(self, force_insert=False, force_update=False, *args, **kwargs):
        reason = self.not_execute_reason if self.not_execute_reason else 'None'
        if self.execution_status != self.__original_execution_status and (self.execution_status not in ['New','Read']):
            complain_topic =  "/CSA/1/" + str(self.pin.username)
            send_push_msg(topic = complain_topic, payload = str(self.id) + ":" + self.execution_status + ":" + reason)
            # send_push_msg(payload = str(self.id) + ":" + self.execution_status)

	self.received_time=self.received_time.replace(tzinfo=None)
        super(Complain, self).save(force_insert, force_update, *args, **kwargs)
        self.__original_execution_status = self.execution_status
        #print timezone.now

    def __str__(self):
        return self.account_no

    class Meta:
       app_label = 'project_data'


class ComplainStatusLog(models.Model):
    complain =  models.ForeignKey(Complain,related_name='stat_complain', on_delete=models.PROTECT)
    bkash_agent = models.ForeignKey(User,related_name='stat_agent', on_delete=models.PROTECT)
    status = models.CharField(max_length=100, null=True)
    change_time = models.DateTimeField(default = timezone.now, blank=True)
    
    def __str__(self):
        return self.bkash_agent

    class Meta:
       app_label = 'project_data'


class Branch(models.Model):
    STATUS_CHOICES = (
        ('', 'Select a Status'),
        ('active', 'Active'),
        ('deactive', 'Deactive'),
    )
    branch_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=100)
    status =  models.CharField(max_length=10, choices = STATUS_CHOICES)
    
    def __str__(self):
        return self.name

    class Meta:
       app_label = 'project_data'

class Region(models.Model):        
    name = models.CharField(max_length=100)
    
    def __str__(self):
        return self.name

    class Meta:
       app_label = 'project_data'


class Notification(models.Model):
    sender = models.ForeignKey(User,related_name='message_sender', on_delete=models.CASCADE)
    message = models.CharField(max_length=500)
    
    def __str__(self):
        return self.sender

    class Meta:
       app_label = 'project_data'
