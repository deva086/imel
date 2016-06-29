from django import template

register = template.Library()

@register.filter(name='get_value')
def get_value(array,index):
	for arra in array:
		if int(arra.id) == int(index):
			return arra.oraganization
	return 'NA'
          
