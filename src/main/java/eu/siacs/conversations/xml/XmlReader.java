package eu.siacs.conversations.xml;

import android.util.Log;
import android.util.Xml;
import eu.siacs.conversations.Config;
import im.conversations.android.xmpp.ExtensionFactory;
import im.conversations.android.xmpp.model.StreamElement;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.jspecify.annotations.NonNull;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class XmlReader implements Closeable {

    private static final int XML_ELEMENT_MAX_DEPTH = 128;

    private final XmlPullParser parser;
    private InputStream is;

    public XmlReader() {
        this.parser = Xml.newPullParser();
        try {
            this.parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
        } catch (XmlPullParserException e) {
            Log.d(Config.LOGTAG, "error setting namespace feature on parser");
        }
    }

    public void setInputStream(final InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IOException();
        }
        this.is = inputStream;
        try {
            parser.setInput(new InputStreamReader(this.is));
        } catch (XmlPullParserException e) {
            throw new IOException("error resetting parser");
        }
    }

    public void reset() throws IOException {
        if (this.is == null) {
            throw new IOException();
        }
        try {
            parser.setInput(new InputStreamReader(this.is));
        } catch (XmlPullParserException e) {
            throw new IOException("error resetting parser");
        }
    }

    @Override
    public void close() {
        this.is = null;
    }

    public @NonNull Tag readTag() throws IOException {
        try {
            while (this.is != null && parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.getEventType() == XmlPullParser.START_TAG) {
                    Tag tag = Tag.start(parser.getName(), parser.getNamespace());
                    for (int i = 0; i < parser.getAttributeCount(); ++i) {
                        // TODO we would also look at parser.getAttributeNamespace()
                        final String prefix = parser.getAttributePrefix(i);
                        String name;
                        if (prefix != null && !prefix.isEmpty()) {
                            name = prefix + ":" + parser.getAttributeName(i);
                        } else {
                            name = parser.getAttributeName(i);
                        }
                        tag.setAttribute(name, parser.getAttributeValue(i));
                    }
                    return tag;
                } else if (parser.getEventType() == XmlPullParser.END_TAG) {
                    return Tag.end(parser.getName());
                } else if (parser.getEventType() == XmlPullParser.TEXT) {
                    return Tag.no(parser.getText());
                }
            }

        } catch (final IOException e) {
            throw e;
        } catch (final Throwable throwable) {
            throw new IOException(
                    "xml parser mishandled "
                            + throwable.getClass().getSimpleName()
                            + "("
                            + throwable.getMessage()
                            + ")",
                    throwable);
        }
        throw new EOFException();
    }

    public <T extends StreamElement> T readElement(final Tag current, final Class<T> clazz)
            throws IOException {
        final Element element = readElement(current);
        if (clazz.isInstance(element)) {
            return clazz.cast(element);
        }
        throw new IOException(
                String.format("Read unexpected {%s}%s", element.getNamespace(), element.getName()));
    }

    public Element readElement(final Tag currentTag) throws IOException {
        return readElement(currentTag, 0);
    }

    private Element readElement(final Tag currentTag, final int depth) throws IOException {
        if (depth >= XML_ELEMENT_MAX_DEPTH) {
            throw new XmlMaxDepthReachedException();
        }
        final var namespace = currentTag.getNamespace();
        final var name = currentTag.getName();
        final Element element = ExtensionFactory.create(name, namespace);
        element.setAttributes(currentTag.getAttributes());
        Tag nextTag = this.readTag();
        if (nextTag.isNo()) {
            element.setContent(nextTag.getName());
            nextTag = this.readTag();
        }
        while (!nextTag.isEnd(element.getName())) {
            if (!nextTag.isNo()) {
                final var child = this.readElement(nextTag, depth + 1);
                element.addChild(child);
            }
            nextTag = this.readTag();
        }
        return element;
    }

    public static class XmlMaxDepthReachedException extends IOException {
        public XmlMaxDepthReachedException() {
            super("Reached maximum depth of XML stream");
        }
    }
}
