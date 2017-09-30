
{% assign sorted_posts = site.posts | sort:"order" %}
{% for post in sorted_posts %}
- *[{{ post.title }}]({{ site.baseurl }}{{ post.url }})*
{% endfor %}
