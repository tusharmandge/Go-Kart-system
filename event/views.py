from datetime import date

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.shortcuts import render, redirect
from django.views.generic import TemplateView

from registration.models import RegistrationRecord
from .forms import EventForm
from .models import EventRecord


# Create your views here.
class EventListView(TemplateView):
    template_name = 'event-list.html'

    def get(self, request, *args, **kwargs):
        request.session['head_name'] = 'event'
        event_list = EventRecord.objects.all().order_by('-event_date')
        return render(request, self.template_name, {'event_list': event_list})


# noinspection PyBroadException
class EventDetail(TemplateView):
    template_name = 'event_detail.html'

    def get(self, request, *args, **kwargs):
        try:
            owner = False
            registered = True
            obj = EventRecord.objects.get(slug=kwargs['slug'])
            if obj.user == request.user or request.user.is_superuser:
                owner = True
            else:
                try:
                    RegistrationRecord.objects.get(user=request.user, event=obj)
                except Exception:
                    registered = False
            return render(request, self.template_name,
                          {'obj': obj, 'owner': owner, 'registered': registered, 'now': date.today()})
        except ObjectDoesNotExist:
            messages.error(request, 'Event Not found')
            return redirect('home')


# noinspection PyBroadException
class AddEvent(TemplateView):
    template_name = 'add_update_event.html'

    def get(self, request, *args, **kwargs):
        try:
            if request.user.is_staff:
                form = EventForm()
            else:
                raise PermissionDenied
            return render(request, self.template_name, {'form': form})
        except PermissionDenied:
            messages.error(request, 'Permission Denied')
            return redirect('home')

    def post(self, request):
        if True:
            if request.user.is_staff:
                form = EventForm(request.POST, request.FILES)
                if form.is_valid():
                    temp = form.save(commit=False)
                    temp.user = request.user
                    form.save()
                    messages.success(request, 'Event Added')
                    return redirect('event:event_detail', slug=temp.slug)
                else:
                    messages.error(request, 'Invalid Input')
            else:
                raise PermissionDenied
            return render(request, self.template_name, {'form': form})
        # except Exception:
        #     messages.error(request, 'Permission Denied')
        #     return redirect('home')


# noinspection PyBroadException
class UpdateEvent(TemplateView):
    template_name = 'add_update_event.html'

    def get(self, request, *args, **kwargs):
        try:
            if request.user.is_staff or request.user.is_superuser:
                obj = EventRecord.objects.get(slug=kwargs['slug'])
                if obj.user == request.user or request.user.is_superuser:
                    form = EventForm(instance=obj)
                else:
                    raise PermissionDenied
            else:
                raise PermissionDenied
            return render(request, self.template_name, {'form': form})
        except Exception:
            messages.error(request, 'Permission Denied')
            return redirect('home')

    def post(self, request, **kwargs):
        try:
            obj = EventRecord.objects.get(slug=kwargs['slug'])
            f = obj.fees
            if obj.user == request.user or request.user.is_superuser:
                form = EventForm(request.POST, request.FILES, instance=obj)
                if form.is_valid():
                    fee = form.cleaned_data['fees']
                    diff = fee - f
                    if diff != 0:
                        student_list = RegistrationRecord.objects.filter(event=obj)
                        for student in student_list:
                            student.balance += diff
                            student.save(update_fields=['balance'])
                    form.save()
                    messages.success(request, 'Event Updated')
                    return redirect('event:event_detail', kwargs['slug'])
                else:
                    messages.error(request, 'Invalid Input')
                return render(request, self.template_name, {'form': form})
            else:
                raise PermissionDenied
        except Exception:
            messages.error(request, 'Permission Denied')
            return redirect('home')


class DeleteEvent(TemplateView):

    def get(self, request, *args, **kwargs):
        try:
            obj = EventRecord.objects.get(slug=kwargs['slug'])
            if str(obj.timestamp) == kwargs['timestamp'] and (obj.user == request.user or request.user.is_superuser):
                if obj.registered_student > 0:
                    raise PermissionDenied('Student Registered, You can not delete this event.')
                obj.delete()
                messages.success(request, 'Event Deleted')
            else:
                raise PermissionDenied('Permission Denied')
        except ObjectDoesNotExist:
            messages.error(request, 'Event Not found')
            return redirect('home')
        except PermissionDenied as msg:
            messages.warning(request, msg)
            return redirect('account:consolidated_view_all')
