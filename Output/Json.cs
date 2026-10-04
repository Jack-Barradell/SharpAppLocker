using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace SharpAppLocker.Output
{
    /// <summary>Minimal dependency-free JSON writer (string/bool/number/Guid/list/dictionary).</summary>
    internal static class Json
    {
        public static string Serialize(object o)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, o);
            return sb.ToString();
        }

        private static void Write(StringBuilder sb, object o)
        {
            if (o == null) { sb.Append("null"); return; }

            if (o is string s) { WriteString(sb, s); return; }
            if (o is bool b) { sb.Append(b ? "true" : "false"); return; }
            if (o is int i) { sb.Append(i.ToString(CultureInfo.InvariantCulture)); return; }
            if (o is long l) { sb.Append(l.ToString(CultureInfo.InvariantCulture)); return; }
            if (o is Guid g) { WriteString(sb, g.ToString()); return; }
            if (o is IDictionary<string, object> d) { WriteObject(sb, d); return; }
            if (o is IEnumerable e) { WriteArray(sb, e); return; }

            WriteString(sb, o.ToString());
        }

        private static void WriteObject(StringBuilder sb, IDictionary<string, object> d)
        {
            sb.Append('{');
            bool first = true;
            foreach (KeyValuePair<string, object> kv in d)
            {
                if (!first) sb.Append(',');
                first = false;
                WriteString(sb, kv.Key);
                sb.Append(':');
                Write(sb, kv.Value);
            }
            sb.Append('}');
        }

        private static void WriteArray(StringBuilder sb, IEnumerable e)
        {
            sb.Append('[');
            bool first = true;
            foreach (object item in e)
            {
                if (!first) sb.Append(',');
                first = false;
                Write(sb, item);
            }
            sb.Append(']');
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}