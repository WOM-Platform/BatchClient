using System;
using System.Collections.Generic;
using System.Text;

namespace ConsoleAppWOMGenerator {

    public class VoucherVerifyPayload {

        /// <summary>
        /// Encrypted payload (represents a <see cref="Content" /> instance).
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// Inner payload encrypted by source.
        /// </summary>
        public class Content {

            public Guid Otc { get; set; }

        }

    }

}
