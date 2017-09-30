
{% assign sorted_posts = site.posts | sort:"order" %}
{% for post in sorted_posts %}
- *[{{ post.title }} - {{ post.description }}]({{ site.baseurl }}{{ post.url }})*
{% endfor %}
