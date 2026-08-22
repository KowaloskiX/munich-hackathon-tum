"""Lookups and conversions shared by every handler group.

Mixed into ``QgisMCPServer`` last, so the domain mixins can rely on these
without importing each other.
"""

from qgis.core import QgsProject
from qgis.PyQt.QtCore import QVariant

from ..compat import LAYER_RASTER, LAYER_VECTOR
from ..errors import CommandError, LayerNotFound, WrongLayerType


class HandlerBase:
    """Layer lookup and value conversion used by every other mixin."""

    @staticmethod
    def _layer(layer_id):
        """The project layer with *layer_id*, or raise :class:`LayerNotFound`.

        Every handler that takes a ``layer_id`` needs exactly this lookup, and
        it used to be open-coded in a dozen of them: a ``mapLayers()``
        membership test, a raise, and a ``mapLayer()`` call, with the wording of
        the error drifting between sites.
        """
        layer = QgsProject.instance().mapLayer(layer_id)
        if layer is None:
            raise LayerNotFound(layer_id)
        return layer

    @classmethod
    def _get_vector_layer(cls, layer_id):
        """The layer with *layer_id*, or raise unless it is a vector layer."""
        layer = cls._layer(layer_id)
        if layer.type() != LAYER_VECTOR:
            raise WrongLayerType(f"Not a vector layer: {layer_id}")
        return layer

    @classmethod
    def _get_raster_layer(cls, layer_id):
        """The layer with *layer_id*, or raise unless it is a raster layer."""
        layer = cls._layer(layer_id)
        if layer.type() != LAYER_RASTER:
            raise WrongLayerType(f"Not a raster layer: {layer_id}")
        return layer

    @staticmethod
    def _pick(mapping, key, label):
        try:
            return mapping[key]
        except KeyError:
            raise CommandError(f"Unknown {label}: {key!r}. Use one of {sorted(mapping)}") from None

    def _is_visible(self, project, layer_id):
        """Visibility of a layer in the layer tree.

        Non-spatial tables (attribute-only tables, e.g. GeoPackage tables used by QGIS relations)
        live in the project but have no node in the layer tree, so findLayer() returns None.
        Treat them as not visible instead of raising AttributeError.
        """
        node = project.layerTreeRoot().findLayer(layer_id)
        return node.isVisible() if node is not None else False

    def _get_layer_type(self, layer):
        if layer.type() == LAYER_VECTOR:
            return f"vector_{layer.geometryType()}"
        elif layer.type() == LAYER_RASTER:
            return "raster"
        else:
            return str(layer.type())

    def _convert_to_python_type(self, qvariant):
        if qvariant.isNull():
            return None
        value = qvariant.value()
        # Tuple form, not `int | float | ...`: PEP 604 unions in isinstance need
        # Python 3.10, and QGIS ships 3.9 well past 3.28 (3.42 still does). The
        # union form raises TypeError there, which broke every feature read.
        if isinstance(value, (int, float, str, bool, type(None))):
            return value
        elif hasattr(value, "toPyDate"):
            return value.toPyDate().isoformat()
        elif hasattr(value, "toPyDateTime"):
            return value.toPyDateTime().isoformat()
        else:
            try:
                return str(value)
            except Exception:
                return None

    def _convert_attribute(self, value):
        """Convert a feature attribute value to a JSON-serializable type."""
        if isinstance(value, QVariant):
            return self._convert_to_python_type(value)
        # Tuple form, not `int | float | ...`: PEP 604 unions in isinstance need
        # Python 3.10, and QGIS ships 3.9 well past 3.28 (3.42 still does). The
        # union form raises TypeError there, which broke every feature read.
        if isinstance(value, (int, float, str, bool, type(None))):
            return value
        try:
            return str(value)
        except Exception:
            return None

    @staticmethod
    def _to_json_safe(val):
        """Convert a QVariant / Qt value to a JSON-serializable Python type."""
        if isinstance(val, QVariant):
            if val.isNull():
                return None
            val = val.value()
        # Qt date/time types → ISO string
        if hasattr(val, "toString"):
            try:
                return val.toString(1)  # Qt.ISODate == 1
            except Exception:
                return str(val)
        if isinstance(val, (str, int, float, bool, type(None))):
            return val
        return str(val)
