using System;
using System.IO;
using System.Linq;

namespace Com.Xenthrax.DllInjector
{
	public class MultiWriter : TextWriter
	{
		#region Constructors
		public MultiWriter(TextWriter BaseWriter)
		{
			this.BaseWriter = TextWriter.Synchronized(BaseWriter);
			this.ExtraWriters = new TextWriter[0];
		}

		public MultiWriter(Stream BaseStream)
		{
			this.BaseWriter = new StreamWriter(BaseStream);
			this.ExtraWriters = new TextWriter[0];
		}

		public MultiWriter(TextWriter BaseWriter, params TextWriter[] ExtraWriters)
		{
			this.BaseWriter = TextWriter.Synchronized(BaseWriter);
			this.ExtraWriters = ExtraWriters.Select(Writer => TextWriter.Synchronized(Writer)).ToArray();
		}

		public MultiWriter(Stream BaseStream, params TextWriter[] ExtraWriters)
		{
			this.BaseWriter = new StreamWriter(BaseStream);
			this.ExtraWriters = ExtraWriters.Select(Writer => TextWriter.Synchronized(Writer)).ToArray();
		}
		#endregion

		#region Members
		public TextWriter BaseWriter { get; protected set; }
		public TextWriter[] ExtraWriters { get; protected set; }
		#endregion

		#region Methods
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				this.BaseWriter.Dispose();

				foreach (TextWriter ExtraWriter in this.ExtraWriters)
					ExtraWriter.Dispose();
			}

			base.Dispose(disposing);
		}

		public override void Close()
		{
			this.BaseWriter.Close();

			foreach (TextWriter ExtraWriter in this.ExtraWriters)
				ExtraWriter.Close();

			base.Close();
		}

		public override void Flush()
		{
			this.BaseWriter.Flush();

			foreach (TextWriter ExtraWriter in this.ExtraWriters)
				ExtraWriter.Flush();

			base.Flush();
		}

		public override void Write(char value)
		{
			this.BaseWriter.Write(value);

			foreach (TextWriter ExtraWriter in this.ExtraWriters)
				ExtraWriter.Write(value);

			base.Write(value);
		}

		public override System.Text.Encoding Encoding
		{
			get
			{
				return this.BaseWriter.Encoding;
			}
		}
		#endregion
	}
}