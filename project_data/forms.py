from django import forms
from project_data.models import Complain, Branch, Notification



class ComplainForm(forms.ModelForm):
    # organization = forms.CharField(label='Organization',required=True)
    # parent_organization = forms.ModelChoiceField(label='Parent Organization',required=True,queryset=Organizations.objects.all(),empty_label="Select an Organization")
    STATUS_CHOICES = (
        ("", "Select a Status"),
        ("Executed", "Executed"),
        ("Not Executed", "Not Executed"),
        ("Escalated", "Escalated "),
    )

    execution_status = forms.ChoiceField(widget = forms.Select(), choices = STATUS_CHOICES, required = True)
    class Meta:
        model = Complain
        fields = ('account_no', 'service_type', 'customer_name', 'balance', 'id_type', 'id_no', 'transaction_id', 'transaction_date_time', 'transaction_amount', 'remarks_of_csa_customer', 'remarks_of_bkash_cs', 'execution_status', 'not_execute_reason')

    def __init__(self, *args, **kwargs):
        edit_check = kwargs.pop('edit_check', False)
        show_status_dropdown = kwargs.pop('show_status_dropdown', False)
        super(ComplainForm, self).__init__(*args, **kwargs)
        if edit_check:
            del self.fields['account_no']
            del self.fields['service_type']
            del self.fields['customer_name']
            del self.fields['balance']
            del self.fields['id_type']
            del self.fields['id_no']
            del self.fields['transaction_id']
            del self.fields['transaction_date_time']
            del self.fields['transaction_amount']
            del self.fields['remarks_of_csa_customer']
        
        if not show_status_dropdown:
            del self.fields['execution_status']


class BranchForm(forms.ModelForm):
    class Meta:
        model = Branch
        fields = ('branch_id','name','address','status')


class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ('message',)