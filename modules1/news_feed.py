import feedparser

class NewsFeed:
    @staticmethod
    def fetch_news():
        feed = feedparser.parse("https://feeds.feedburner.com/TheHackersNews")
        return [{"title": entry.title, "link": entry.link, "published": entry.published} for entry in feed.entries[:6]]